/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "headers/shared.h"
#include "headers/sec.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"

/* Prototypes */
static void __memclear(char *id, char *name, char *ip, char *key, size_t size) __attribute((nonnull));
static void __chash(keystore *keys, const char *id, const char *name, char *ip, const char *key) __attribute((nonnull));

static int pass_empty_keyfile = 0;

/* Clear keys entries */
static void __memclear(char *id, char *name, char *ip, char *key, size_t size)
{
    memset(id, '\0', size);
    memset(name, '\0', size);
    memset(key, '\0', size);
    memset(ip, '\0', size);
}

/* Create the final key */
static void __chash(keystore *keys, const char *id, const char *name, char *ip, const char *key)
{
    os_md5 filesum1;
    os_md5 filesum2;

    char *tmp_str;
    char _finalstr[KEYSIZE];

    /* Allocate for the whole structure */
    keys->keyentries = (keyentry **)realloc(keys->keyentries,
                                            (keys->keysize + 1) * sizeof(keyentry *));
    if (!keys->keyentries) {
        ErrorExit(MEM_ERROR, __local_name, errno, strerror(errno));
    }
    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);

    /* Set configured values for id */
    os_strdup(id, keys->keyentries[keys->keysize]->id);
    OSHash_Add(keys->keyhash_id,
               keys->keyentries[keys->keysize]->id,
               keys->keyentries[keys->keysize]);

    /* Agent IP */
    os_calloc(1, sizeof(os_ip), keys->keyentries[keys->keysize]->ip);
    if (OS_IsValidIP(ip, keys->keyentries[keys->keysize]->ip) == 0) {
        ErrorExit(INVALID_IP, __local_name, ip);
    }

    /* We need to remove the "/" from the CIDR */
    if ((tmp_str = strchr(keys->keyentries[keys->keysize]->ip->ip, '/')) != NULL) {
        *tmp_str = '\0';
    }
    OSHash_Add(keys->keyhash_ip,
               keys->keyentries[keys->keysize]->ip->ip,
               keys->keyentries[keys->keysize]);

    /* Agent name */
    os_strdup(name, keys->keyentries[keys->keysize]->name);

    /* Initialize the variables */
    keys->keyentries[keys->keysize]->rcvd = 0;
    keys->keyentries[keys->keysize]->local = 0;
    keys->keyentries[keys->keysize]->keyid = keys->keysize;
    keys->keyentries[keys->keysize]->global = 0;
    keys->keyentries[keys->keysize]->fp = NULL;
    keys->keyentries[keys->keysize]->inode = 0;
    keys->keyentries[keys->keysize]->crypto_method = W_METH_AES;
    pthread_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);

    /** Generate final symmetric key **/

    /* MD5 from name, id and key */
    OS_MD5_Str(name, filesum1);
    OS_MD5_Str(id,  filesum2);

    /* Generate new filesum1 */
    snprintf(_finalstr, sizeof(_finalstr) - 1, "%s%s", filesum1, filesum2);

    /* Use just half of the first MD5 (name/id) */
    OS_MD5_Str(_finalstr, filesum1);
    filesum1[15] = '\0';
    filesum1[16] = '\0';

    /* Second md is just the key */
    OS_MD5_Str(key, filesum2);

    /* Generate final key */
    snprintf(_finalstr, 49, "%s%s", filesum2, filesum1);

    /* Final key is 48 * 4 = 192bits */
    os_strdup(_finalstr, keys->keyentries[keys->keysize]->key);

    /* Clean final string from memory */
    memset_secure(_finalstr, '\0', sizeof(_finalstr));

    /* Ready for next */
    keys->keysize++;

    return;
}

/* Check if the authentication key file is present */
int OS_CheckKeys()
{
    FILE *fp;

    if (File_DateofChange(KEYSFILE_PATH) < 0) {
        merror(NO_AUTHFILE, __local_name, KEYSFILE_PATH);
        merror(NO_CLIENT_KEYS, __local_name);
        return (0);
    }

    fp = fopen(KEYSFILE_PATH, "r");
    if (!fp) {
        /* We can leave from here */
        merror(FOPEN_ERROR, __local_name, KEYSFILE_PATH, errno, strerror(errno));
        merror(NO_AUTHFILE, __local_name, KEYSFILE_PATH);
        merror(NO_CLIENT_KEYS, __local_name);
        return (0);
    }

    fclose(fp);

    /* Authentication keys are present */
    return (1);
}

/* Read the authentication keys */
void OS_ReadKeys(keystore *keys)
{
    FILE *fp;

    char buffer[OS_BUFFER_SIZE + 1];

    char name[KEYSIZE + 1];
    char ip[KEYSIZE + 1];
    char id[KEYSIZE + 1];
    char key[KEYSIZE + 1];

    /* Check if the keys file is present and we can read it */
    if ((keys->file_change = File_DateofChange(KEYS_FILE)) < 0) {
        merror(NO_AUTHFILE, __local_name, KEYS_FILE);
        ErrorExit(NO_CLIENT_KEYS, __local_name);

    }
    fp = fopen(KEYS_FILE, "r");
    if (!fp) {
        /* We can leave from here */
        merror(FOPEN_ERROR, __local_name, KEYS_FILE, errno, strerror(errno));
        ErrorExit(NO_CLIENT_KEYS, __local_name);

    }

    /* Initialize hashes */
    keys->keyhash_id = OSHash_Create();
    keys->keyhash_ip = OSHash_Create();
    if (!keys->keyhash_id || !keys->keyhash_ip) {
        ErrorExit(MEM_ERROR, __local_name, errno, strerror(errno));
    }

    /* Initialize structure. Callers that already have a live keystore
     * (remoted reload) must OS_FreeKeys first so sender_fp is closed.
     * Do not fclose sender_fp here: CLI tools stack-allocate an
     * uninitialized keystore and a garbage FILE* would be closed.
     */
    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->sender_fp = NULL;
    keys->sender_inode = 0;

    /* Zero the buffers */
    __memclear(id, name, ip, key, KEYSIZE + 1);
    memset(buffer, '\0', OS_BUFFER_SIZE + 1);

    /* Read each line. Lines are divided as "id name ip key" */
    while (fgets(buffer, OS_BUFFER_SIZE, fp) != NULL) {
        char *tmp_str;
        char *valid_str;

        if ((buffer[0] == '#') || (buffer[0] == ' ')) {
            continue;
        }

        /* Get ID */
        valid_str = buffer;
        tmp_str = strchr(buffer, ' ');
        if (!tmp_str) {
            merror(INVALID_KEY, __local_name, buffer);
            continue;
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(id, valid_str, KEYSIZE - 1);

        /* Removed entry */
        if (*tmp_str == '#') {
            continue;
        }

        /* Get name */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        if (!tmp_str) {
            merror(INVALID_KEY, __local_name, buffer);
            continue;
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(name, valid_str, KEYSIZE - 1);

        /* Get IP address */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        if (!tmp_str) {
            merror(INVALID_KEY, __local_name, buffer);
            continue;
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(ip, valid_str, KEYSIZE - 1);

        /* Get key */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }

        strncpy(key, valid_str, KEYSIZE - 1);

        /* Generate the key hash */
        __chash(keys, id, name, ip, key);

        /* Clear the memory */
        __memclear(id, name, ip, key, KEYSIZE + 1);

        /* Check for maximum agent size */
        if (keys->keysize >= (MAX_AGENTS - 2)) {
            merror(AG_MAX_ERROR, __local_name, MAX_AGENTS - 2);
            ErrorExit(CONFIG_ERROR, __local_name, KEYS_FILE);
        }

        continue;
    }

    /* Close key file */
    fclose(fp);

    /* Clear one last time before leaving */
    __memclear(id, name, ip, key, KEYSIZE + 1);

    /* Check if there are any agents available */
    if (keys->keysize == 0) {
        merror(NO_CLIENT_KEYS, __local_name);
        if (!pass_empty_keyfile) {
            exit(1);
        }
    }

    return;
}

/* Free the auth keys.
 * remoted must hold key_lock_write() — there is no sleep-to-drain window.
 */
void OS_FreeKeys(keystore *keys)
{
    unsigned int i = 0;
    unsigned int _keysize = 0;
    OSHash *hashid;
    OSHash *haship;

    _keysize = keys->keysize;
    keys->keysize = 0;
    hashid = keys->keyhash_id;
    haship = keys->keyhash_ip;

    keys->keyhash_id = NULL;
    keys->keyhash_ip = NULL;

    /* Free the hashes */
    if (hashid) {
        OSHash_Free(hashid);
    }
    if (haship) {
        OSHash_Free(haship);
    }

    if (keys->sender_fp) {
        OS_CloseSenderCounter(keys);
    }

    for (i = 0; i < _keysize; i++) {
        if (keys->keyentries[i]) {
            if (keys->keyentries[i]->ip) {
                free(keys->keyentries[i]->ip->ip);
                free(keys->keyentries[i]->ip);
            }

            if (keys->keyentries[i]->id) {
                free(keys->keyentries[i]->id);
            }

            if (keys->keyentries[i]->key) {
                free(keys->keyentries[i]->key);
            }

            if (keys->keyentries[i]->name) {
                free(keys->keyentries[i]->name);
            }

            /* Close counter */
            if (keys->keyentries[i]->fp) {
                fclose(keys->keyentries[i]->fp);
            }

            pthread_mutex_destroy(&keys->keyentries[i]->mutex);

            free(keys->keyentries[i]);
            keys->keyentries[i] = NULL;
        }
    }

    /* Free structure */
    free(keys->keyentries);
    keys->keyentries = NULL;
    keys->keysize = 0;
}

/* Check if key changed */
int OS_CheckUpdateKeys(const keystore *keys)
{
    if (keys->file_change !=  File_DateofChange(KEYS_FILE)) {
        return (1);
    }
    return (0);
}

/* Update the keys if changed */
int OS_UpdateKeys(keystore *keys)
{
    unsigned int i;
    unsigned int saved_count;
    struct {
        char *id;
        char *ip;
        time_t rcvd;
        struct sockaddr_storage peer_info;
        crypt_method crypto_method;
    } *saved = NULL;

    if (keys->file_change == File_DateofChange(KEYS_FILE)) {
        return (0);
    }

    merror(ENCFILE_CHANGED, __local_name);
    debug1("%s: DEBUG: Freekeys", __local_name);

    saved_count = keys->keysize;
    if (saved_count > 0) {
        os_calloc(saved_count, sizeof(*saved), saved);
        for (i = 0; i < saved_count; i++) {
            if (!keys->keyentries[i] || !keys->keyentries[i]->id) {
                continue;
            }
            os_strdup(keys->keyentries[i]->id, saved[i].id);
            if (keys->keyentries[i]->ip && keys->keyentries[i]->ip->ip) {
                os_strdup(keys->keyentries[i]->ip->ip, saved[i].ip);
            }
            saved[i].rcvd = keys->keyentries[i]->rcvd;
            saved[i].peer_info = keys->keyentries[i]->peer_info;
            saved[i].crypto_method = keys->keyentries[i]->crypto_method;
        }
    }

    OS_FreeKeys(keys);
    debug1("%s: DEBUG: OS_ReadKeys", __local_name);

    /* Read keys */
    verbose(ENC_READ, __local_name);

    OS_ReadKeys(keys);
    debug1("%s: DEBUG: OS_StartCounter", __local_name);

    OS_StartCounter(keys);

    if (saved) {
        for (i = 0; i < saved_count; i++) {
            int id;

            if (!saved[i].id) {
                continue;
            }
            id = OS_IsAllowedID(keys, saved[i].id);
            if (id >= 0 && saved[i].ip && keys->keyentries[id]->ip &&
                    keys->keyentries[id]->ip->ip &&
                    strcmp(keys->keyentries[id]->ip->ip, saved[i].ip) == 0) {
                keys->keyentries[id]->rcvd = saved[i].rcvd;
                keys->keyentries[id]->peer_info = saved[i].peer_info;
                keys->keyentries[id]->crypto_method = saved[i].crypto_method;
            }
            free(saved[i].id);
            free(saved[i].ip);
        }
        free(saved);
    }

    debug1("%s: DEBUG: OS_UpdateKeys completed", __local_name);
    return (1);
}

/* Check if an IP address is allowed to connect */
int OS_IsAllowedIP(keystore *keys, const char *srcip)
{
    keyentry *entry;

    if (srcip == NULL) {
        return (-1);
    }

    entry = (keyentry *) OSHash_Get(keys->keyhash_ip, srcip);
    if (entry) {
        return ((int)entry->keyid);
    }

    return (-1);
}

/* Check if the agent name is valid */
int OS_IsAllowedName(const keystore *keys, const char *name)
{
    unsigned int i = 0;

    for (i = 0; i < keys->keysize; i++) {
        if (strcmp(keys->keyentries[i]->name, name) == 0) {
            return ((int)i);
        }
    }

    return (-1);
}

int OS_IsAllowedID(keystore *keys, const char *id)
{
    keyentry *entry;

    if (id == NULL) {
        return (-1);
    }

    entry = (keyentry *) OSHash_Get(keys->keyhash_id, id);
    if (entry) {
        return ((int)entry->keyid);
    }
    return (-1);
}


/* Used for dynamic IP addresses */
int OS_IsAllowedDynamicID(keystore *keys, const char *id, const char *srcip)
{
    keyentry *entry;

    if (id == NULL) {
        return (-1);
    }

    entry = (keyentry *) OSHash_Get(keys->keyhash_id, id);
    if (entry) {
        if (OS_IPFound(srcip, entry->ip)) {
            return ((int)entry->keyid);
        }
    }

    return (-1);
}
 /* Configure to pass if keys file is empty */
 void OS_PassEmptyKeyfile() {
     pass_empty_keyfile = 1;
 }
