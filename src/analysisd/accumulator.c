/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Accumulator Functions which accumulate objects based on an ID.
 *
 * Pipeline process workers bind a private OSHash via analysisd_set_acm_store()
 * (TLS), so Accumulate runs lock-free per shard. Cross-shard accumulation for
 * the same hostname+decoder+id key is intentional non-sharing (rare). The
 * global store + accumulate_mutex remain for Accumulate_Init / serial paths
 * (testrule, non-pipeline) when TLS is unset.
 */

#include <sys/time.h>

#include "shared.h"
#include "accumulator.h"
#include "eventinfo.h"

/* Global fallback store (serial / testrule). */
static OSHash *acm_store = NULL;
static pthread_mutex_t accumulate_mutex = PTHREAD_MUTEX_INITIALIZER;
static int acm_lookups = 0;
static time_t acm_purge_ts = 0;

/* Per-process-thread shard store (pipeline). */
static __thread OSHash *tls_acm_store = NULL;
static __thread int tls_acm_lookups = 0;
static __thread time_t tls_acm_purge_ts = 0;

/* Accumulator Constants */
#define OS_ACM_EXPIRE_ELM      120
#define OS_ACM_PURGE_INTERVAL  300
#define OS_ACM_PURGE_COUNT     200

/* Accumulator Max Values */
#define OS_ACM_MAXKEY 256
#define OS_ACM_MAXELM 81

typedef struct _OS_ACM_Store {
    time_t timestamp;
    char *dstuser;
    char *srcuser;
    char *dstip;
    char *srcip;
    char *dstport;
    char *srcport;
    char *data;
} OS_ACM_Store;

/* Internal Functions */
static int acm_str_replace(char **dst, const char *src);
static OS_ACM_Store *InitACMStore(void);
static void FreeACMStore(OS_ACM_Store *obj);
static void Accumulate_CleanUp_Store(OSHash *store, int *lookups, time_t *purge_ts);

void analysisd_set_acm_store(OSHash *store)
{
    tls_acm_store = store;
    tls_acm_lookups = 0;
    tls_acm_purge_ts = 0;
}

OSHash *analysisd_get_acm_store(void)
{
    return tls_acm_store ? tls_acm_store : acm_store;
}

OSHash *Accumulate_CreateStore(void)
{
    OSHash *store;

    store = OSHash_Create();
    if (!store) {
        merror(LIST_ERROR, ARGV0);
        return NULL;
    }
    if (!OSHash_setSize(store, 2048)) {
        merror(LIST_ERROR, ARGV0);
        OSHash_Free(store);
        return NULL;
    }
    return store;
}

void Accumulate_DestroyStore(OSHash *store)
{
    unsigned int ti;
    OSHashNode *curr;
    OSHashNode *next;
    OS_ACM_Store *stored_data;

    if (!store) {
        return;
    }

    /* Free payload before OSHash_Free (which frees keys/nodes only). */
    for (ti = 0; ti <= store->rows; ti++) {
        curr = store->table[ti];
        while (curr != NULL) {
            next = curr->next;
            stored_data = (OS_ACM_Store *)curr->data;
            FreeACMStore(stored_data);
            curr->data = NULL;
            curr = next;
        }
    }

    OSHash_Free(store);
}

/* Start the Accumulator module (global fallback for serial paths). */
int Accumulate_Init()
{
    struct timeval tp;

    acm_store = Accumulate_CreateStore();
    if (!acm_store) {
        return (0);
    }

    gettimeofday(&tp, NULL);
    acm_purge_ts = tp.tv_sec;

    debug1("%s: DEBUG: Accumulator Init completed.", ARGV0);
    return (1);
}

/* Accumulate data from events sharing the same ID */
Eventinfo *Accumulate(Eventinfo *lf)
{
    int result;
    int do_update = 0;
    int locked = 0;

    char _key[OS_ACM_MAXKEY];
    OS_ACM_Store *stored_data = 0;
    OSHash *store;
    int *lookups;
    time_t *purge_ts;

    time_t current_ts;
    struct timeval tp;

    if (lf == NULL) {
        debug1("accumulator: DEBUG: Received NULL EventInfo");
        return lf;
    }
    if (lf->id == NULL) {
        debug2("accumulator: DEBUG: No id available");
        return lf;
    }
    if (lf->decoder_info == NULL) {
        debug1("accumulator: DEBUG: No decoder_info available");
        return lf;
    }
    if (lf->decoder_info->name == NULL) {
        debug1("%s: DEBUG: No decoder name available", ARGV0);
        return lf;
    }

    if (tls_acm_store) {
        store = tls_acm_store;
        lookups = &tls_acm_lookups;
        purge_ts = &tls_acm_purge_ts;
    } else {
        store = acm_store;
        lookups = &acm_lookups;
        purge_ts = &acm_purge_ts;
        os_mutex_lock(&accumulate_mutex);
        locked = 1;
    }

    if (!store) {
        if (locked) {
            os_mutex_unlock(&accumulate_mutex);
        }
        return lf;
    }

    Accumulate_CleanUp_Store(store, lookups, purge_ts);

    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    result = snprintf(_key, OS_FLSIZE, "%s %s %s",
                      lf->hostname,
                      lf->decoder_info->name,
                      lf->id
                     );
    if (result < 0 || (unsigned)result >= sizeof(_key)) {
        debug1("accumulator: DEBUG: error setting accumulator key, id:%s,name:%s",
               lf->id, lf->decoder_info->name);
        if (locked) {
            os_mutex_unlock(&accumulate_mutex);
        }
        return lf;
    }

    if ((stored_data = (OS_ACM_Store *)OSHash_Get(store, _key)) != NULL) {
        debug2("accumulator: DEBUG: Lookup for '%s' found a stored value!", _key);

        if (stored_data->timestamp > 0 && stored_data->timestamp < current_ts - OS_ACM_EXPIRE_ELM) {
            if (OSHash_Delete(store, _key) != NULL) {
                debug1("accumulator: DEBUG: Deleted expired hash entry for '%s'", _key);
                FreeACMStore(stored_data);
                stored_data = InitACMStore();
            }
        } else {
            do_update = 1;
            if (acm_str_replace(&lf->dstuser, stored_data->dstuser) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->dstuser to %s", _key, lf->dstuser);
            }

            if (acm_str_replace(&lf->srcuser, stored_data->srcuser) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->srcuser to %s", _key, lf->srcuser);
            }

            if (acm_str_replace(&lf->dstip, stored_data->dstip) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->dstip to %s", _key, lf->dstip);
            }

            if (acm_str_replace(&lf->srcip, stored_data->srcip) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->srcip to %s", _key, lf->srcip);
            }

            if (acm_str_replace(&lf->dstport, stored_data->dstport) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->dstport to %s", _key, lf->dstport);
            }

            if (acm_str_replace(&lf->srcport, stored_data->srcport) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->srcport to %s", _key, lf->srcport);
            }

            if (acm_str_replace(&lf->data, stored_data->data) == 0) {
                debug2("accumulator: DEBUG: (%s) updated lf->data to %s", _key, lf->data);
            }
        }
    } else {
        stored_data = InitACMStore();
    }

    stored_data->timestamp = current_ts;
    if (acm_str_replace(&stored_data->dstuser, lf->dstuser) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstuser to %s",
               _key, stored_data->dstuser);
    }

    if (acm_str_replace(&stored_data->srcuser, lf->srcuser) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcuser to %s",
               _key, stored_data->srcuser);
    }

    if (acm_str_replace(&stored_data->dstip, lf->dstip) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstip to %s",
               _key, stored_data->dstip);
    }

    if (acm_str_replace(&stored_data->srcip, lf->srcip) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcip to %s",
               _key, stored_data->srcip);
    }

    if (acm_str_replace(&stored_data->dstport, lf->dstport) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstport to %s",
               _key, stored_data->dstport);
    }

    if (acm_str_replace(&stored_data->srcport, lf->srcport) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcport to %s",
               _key, stored_data->srcport);
    }

    if (acm_str_replace(&stored_data->data, lf->data) == 0) {
        debug2("accumulator: DEBUG: (%s) updated stored_data->data to %s",
               _key, stored_data->data);
    }

    if (do_update == 1) {
        if ((result = OSHash_Update(store, _key, stored_data)) != 1) {
            verbose("accumulator: ERROR: Update of stored data for %s failed (%d).",
                    _key, result);
        } else {
            debug1("accumulator: DEBUG: Updated stored data for %s", _key);
        }
    } else {
        if ((result = OSHash_Add(store, _key, stored_data)) != 2) {
            verbose("accumulator: ERROR: Addition of stored data for %s failed (%d).",
                    _key, result);
        } else {
            debug1("accumulator: DEBUG: Added stored data for %s", _key);
        }
    }

    if (locked) {
        os_mutex_unlock(&accumulate_mutex);
    }
    return lf;
}

void Accumulate_CleanUp(void)
{
    if (tls_acm_store) {
        Accumulate_CleanUp_Store(tls_acm_store, &tls_acm_lookups, &tls_acm_purge_ts);
        return;
    }

    os_mutex_lock(&accumulate_mutex);
    if (acm_store) {
        Accumulate_CleanUp_Store(acm_store, &acm_lookups, &acm_purge_ts);
    }
    os_mutex_unlock(&accumulate_mutex);
}

static void Accumulate_CleanUp_Store(OSHash *store, int *lookups, time_t *purge_ts)
{
    struct timeval tp;
    time_t current_ts = 0;
    int expired = 0;

    OSHashNode *curr;
    OS_ACM_Store *stored_data;
    char *key;
    unsigned int ti;

    (*lookups)++;

    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    if (*lookups < OS_ACM_PURGE_COUNT && *purge_ts < current_ts + OS_ACM_PURGE_INTERVAL) {
        return;
    }
    debug1("accumulator: DEBUG: Accumulator_CleanUp() running .. ");

    *lookups = 0;
    *purge_ts = current_ts;

    for (ti = 0; ti < store->rows; ti++) {
        curr = store->table[ti];
        while (curr != NULL) {
            key = (char *)curr->key;
            stored_data = (OS_ACM_Store *)curr->data;
            curr = curr->next;

            debug2("accumulator: DEBUG: CleanUp() evaluating cached key: %s ", key);
            if (stored_data != NULL) {
                debug2("accumulator: DEBUG: CleanUp() elm:%ld, curr:%ld",
                       (long int)stored_data->timestamp, (long int)current_ts);
                if (stored_data->timestamp < current_ts - OS_ACM_EXPIRE_ELM) {
                    debug2("accumulator: DEBUG: CleanUp() Expiring '%s'", key);
                    if (OSHash_Delete(store, key) != NULL) {
                        FreeACMStore(stored_data);
                        expired++;
                    } else {
                        debug1("accumulator: DEBUG: CleanUp() failed to find key '%s'", key);
                    }
                }
            }
        }
    }
    debug1("accumulator: DEBUG: Expired %d elements", expired);
}

/* Initialize a storage object */
static OS_ACM_Store *InitACMStore(void)
{
    OS_ACM_Store *obj;
    os_calloc(1, sizeof(OS_ACM_Store), obj);

    obj->timestamp = 0;
    obj->srcuser = NULL;
    obj->dstuser = NULL;
    obj->srcip = NULL;
    obj->dstip = NULL;
    obj->srcport = NULL;
    obj->dstport = NULL;
    obj->data = NULL;

    return obj;
}

/* Free an accumulation store struct */
static void FreeACMStore(OS_ACM_Store *obj)
{
    if (obj != NULL) {
        debug2("accumulator: DEBUG: Freeing an accumulator struct.");
        free(obj->dstuser);
        free(obj->srcuser);
        free(obj->dstip);
        free(obj->srcip);
        free(obj->dstport);
        free(obj->srcport);
        free(obj->data);
        free(obj);
    }
}

static int acm_str_replace(char **dst, const char *src)
{
    int result = 0;

    if (src == NULL) {
        return -1;
    }

    if (*dst != NULL && **dst != '\0') {
        return -1;
    }

    size_t slen = strlen(src);
    if (slen <= 0 || slen > OS_ACM_MAXELM - 1) {
        return -1;
    }

    if (*dst != NULL) {
        free(*dst);
    }
    os_malloc(slen + 1, *dst);

    result = strcpy(*dst, src) == NULL ? -1 : 0;
    if (result < 0) {
        debug1("accumulator: DEBUG: error in acm_str_replace()");
    }
    return result;
}
