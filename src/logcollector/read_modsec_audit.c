/* Copyright (C) 2026 OSSEC Project
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

/* Serial ModSecurity / libmodsecurity audit logs use section markers:
 *   --abcd1234-A-- ... --abcd1234-H-- ... --abcd1234-Z--
 * Accumulate lines from a matching -A-- through the same-id -Z-- trailer.
 *
 * Transaction IDs are bound across sections so a crafted request/response
 * body line that looks like "--evil-Z--" cannot prematurely end (or forge)
 * an audit event (#1390 security review).
 */

#define MODSEC_MAX_CACHE 96
#define MODSEC_ID_MAX    64

typedef struct {
    char id[MODSEC_ID_MAX];
    size_t id_len;
} modsec_txn_t;

/* Parse "--<id>-X--" into id and section. Returns 1 on success. */
static int parse_modsec_boundary(const char *line, char *id_out, size_t id_cap,
                                 size_t *id_len_out, char *section_out)
{
    const char *p;
    size_t id_len = 0;

    if (!line || !id_out || !section_out || id_cap < 2) {
        return 0;
    }

    if (line[0] != '-' || line[1] != '-') {
        return 0;
    }

    p = line + 2;
    while (((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z')) &&
           id_len + 1 < id_cap) {
        id_out[id_len++] = *p++;
    }

    /* Require a non-empty, fully-consumed id (no truncation mid-id). */
    if (id_len == 0) {
        return 0;
    }
    if ((*p >= '0' && *p <= '9') ||
        (*p >= 'a' && *p <= 'z') ||
        (*p >= 'A' && *p <= 'Z')) {
        return 0; /* id longer than id_cap - 1 */
    }

    /* Expect "-X--" after the id */
    if (p[0] != '-' || p[1] == '\0' || p[2] != '-' || p[3] != '-') {
        return 0;
    }
    if (p[4] != '\0' && p[4] != '\r') {
        return 0;
    }

    id_out[id_len] = '\0';
    if (id_len_out) {
        *id_len_out = id_len;
    }
    *section_out = p[1];
    return 1;
}

static int txn_id_eq(const modsec_txn_t *txn, const char *id, size_t id_len)
{
    return (txn->id_len == id_len &&
            txn->id_len > 0 &&
            memcmp(txn->id, id, id_len) == 0);
}

static void txn_clear(modsec_txn_t *txn)
{
    txn->id[0] = '\0';
    txn->id_len = 0;
}

static void txn_set(modsec_txn_t *txn, const char *id, size_t id_len)
{
    if (id_len >= MODSEC_ID_MAX) {
        id_len = MODSEC_ID_MAX - 1;
    }
    memcpy(txn->id, id, id_len);
    txn->id[id_len] = '\0';
    txn->id_len = id_len;
}

static void modsec_free_cache(char **cache, int top)
{
    int i;

    for (i = 0; i < top; i++) {
        free(cache[i]);
        cache[i] = NULL;
    }
}

static void modsec_send_msg(char **cache, int top, const char *file, int drop_it)
{
    int i;
    size_t n = 0;
    size_t z;
    char message[OS_MAXSTR];

    message[0] = '\0';

    for (i = 0; i < top; i++) {
        z = strlen(cache[i]);

        /* Cap join length; still free every cache entry. */
        if (n + z + 1 < OS_MAXSTR) {
            if (n > 0) {
                message[n++] = ' ';
            }
            memcpy(message + n, cache[i], z);
            n += z;
            message[n] = '\0';
        }

        free(cache[i]);
        cache[i] = NULL;
    }

    if (!drop_it && n > 0) {
        if (SendMSG(logr_queue, message, file, LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND, ARGV0);
            if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }
        }
    }
}

void *read_modsec_audit(int pos, int *rc, int drop_it)
{
    char *cache[MODSEC_MAX_CACHE];
    int icache = 0;
    char buffer[OS_MAXSTR];
    char *p;
    long offset;
    long txn_start = -1;
    modsec_txn_t txn;
    char bid[MODSEC_ID_MAX];
    size_t bid_len = 0;
    char section = '\0';

    memset(cache, 0, sizeof(cache));
    txn_clear(&txn);
    *rc = 0;

    offset = ftell(logff[pos].fp);
    if (offset < 0) {
        merror(FTELL_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
        return NULL;
    }

    while (fgets(buffer, OS_MAXSTR, logff[pos].fp)) {
        if ((p = strchr(buffer, '\n')) != NULL) {
            *p = '\0';
        } else {
            if (strlen(buffer) == OS_MAXSTR - 1) {
                /* Discard remainder of overlong line; do not treat as a marker. */
                while (fgets(buffer, OS_MAXSTR, logff[pos].fp) &&
                       !strchr(buffer, '\n')) {
                }
                offset = ftell(logff[pos].fp);
                continue;
            }
            debug1("%s: Message not complete. Trying again: '%s'", ARGV0, buffer);
            if (fseek(logff[pos].fp, offset, SEEK_SET) < 0) {
                merror(FSEEK_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
                break;
            }
            break;
        }

#ifdef WIN32
        if ((p = strrchr(buffer, '\r')) != NULL) {
            *p = '\0';
        }
#endif

        /* Skip empty lines between transactions */
        if (buffer[0] == '\0' && icache == 0) {
            offset = ftell(logff[pos].fp);
            continue;
        }

        if (parse_modsec_boundary(buffer, bid, sizeof(bid), &bid_len, &section)) {
            if (section == 'A' && icache == 0) {
                /* Start of a new transaction (only when not already inside one). */
                txn_set(&txn, bid, bid_len);
                txn_start = offset;
                os_strdup(buffer, cache[icache]);
                icache = 1;
            } else if (txn.id_len > 0 && txn_id_eq(&txn, bid, bid_len)) {
                /* Same-id section marker (-B--, -H--, -Z--, ...). */
                if (icache >= MODSEC_MAX_CACHE) {
                    merror("%s: WARN: ModSecurity audit entry exceeded %d "
                           "lines; discarding event from '%s'",
                           ARGV0, MODSEC_MAX_CACHE, logff[pos].file);
                    modsec_free_cache(cache, icache);
                    icache = 0;
                    txn_clear(&txn);
                    txn_start = -1;
                } else {
                    os_strdup(buffer, cache[icache]);
                    icache++;
                }

                if (section == 'Z' && icache > 0 && txn.id_len > 0) {
                    modsec_send_msg(cache, icache, logff[pos].file, drop_it);
                    icache = 0;
                    txn_clear(&txn);
                    txn_start = -1;
                }
            } else if (icache > 0) {
                /* Lookalike marker inside request/response body: keep as data,
                 * do not retarget the open transaction. */
                if (icache >= MODSEC_MAX_CACHE) {
                    merror("%s: WARN: ModSecurity audit entry exceeded %d "
                           "lines; discarding event from '%s'",
                           ARGV0, MODSEC_MAX_CACHE, logff[pos].file);
                    modsec_free_cache(cache, icache);
                    icache = 0;
                    txn_clear(&txn);
                    txn_start = -1;
                } else {
                    os_strdup(buffer, cache[icache]);
                    icache++;
                }
            }
            /* else: marker noise outside a transaction — ignore */
        } else if (txn.id_len > 0) {
            /* Body / header line inside an open transaction. */
            if (icache >= MODSEC_MAX_CACHE) {
                merror("%s: WARN: ModSecurity audit entry exceeded %d lines; "
                       "discarding event from '%s'",
                       ARGV0, MODSEC_MAX_CACHE, logff[pos].file);
                modsec_free_cache(cache, icache);
                icache = 0;
                txn_clear(&txn);
                txn_start = -1;
            } else {
                os_strdup(buffer, cache[icache]);
                icache++;
            }
        }
        /* else: noise outside a transaction — ignore */

        offset = ftell(logff[pos].fp);
        if (offset < 0) {
            merror(FTELL_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
            break;
        }
    }

    /* Incomplete transaction — rewind to its start for the next read cycle */
    if (icache > 0) {
        modsec_free_cache(cache, icache);
        if (txn_start >= 0 && fseek(logff[pos].fp, txn_start, SEEK_SET) < 0) {
            merror(FSEEK_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
        }
    }

    return NULL;
}
