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
 * Accumulate lines until the Z (trailer) section, then emit one event.
 */

#define MODSEC_MAX_CACHE 96

static int is_modsec_boundary(const char *line, char section)
{
    const char *p;

    if (!line || line[0] != '-' || line[1] != '-') {
        return 0;
    }

    p = line + 2;
    while ((*p >= '0' && *p <= '9') ||
           (*p >= 'a' && *p <= 'z') ||
           (*p >= 'A' && *p <= 'Z')) {
        p++;
    }

    /* Expect "-X--" after the id (X = section letter) */
    if (p[0] != '-' || p[1] != section || p[2] != '-' || p[3] != '-') {
        return 0;
    }

    if (p[4] != '\0' && p[4] != '\r') {
        return 0;
    }

    return 1;
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

    memset(cache, 0, sizeof(cache));
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
                while (fgets(buffer, OS_MAXSTR, logff[pos].fp) &&
                       !strchr(buffer, '\n')) {
                    /* discard rest of overlong line */
                }
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

        if (icache == 0) {
            txn_start = offset;
        }

        if (icache >= MODSEC_MAX_CACHE) {
            merror("%s: WARN: ModSecurity audit entry exceeded %d lines; "
                   "sending partial event from '%s'",
                   ARGV0, MODSEC_MAX_CACHE, logff[pos].file);
            modsec_send_msg(cache, icache, logff[pos].file, drop_it);
            icache = 0;
            txn_start = -1;
        }

        os_strdup(buffer, cache[icache]);
        icache++;

        if (is_modsec_boundary(buffer, 'Z')) {
            modsec_send_msg(cache, icache, logff[pos].file, drop_it);
            icache = 0;
            txn_start = -1;
        }

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
