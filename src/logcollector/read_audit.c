/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

#define MAX_CACHE 16
#define MAX_HEADER 64

/* Compile message from cache and send through queue */
static void audit_send_msg(char **cache, int top, const char *file, int drop_it) {
    int i;
    size_t n = 0;
    size_t z;
    char message[OS_MAXSTR];

    message[0] = '\0';

    for (i = 0; i < top; i++) {
        z = strlen(cache[i]);

        /* Cap join length; only copied records advance n. Still free every
         * cache entry. Same form as modsec_send_msg().
         */
        if (n + z + 1 < sizeof(message)) {
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

void *read_audit(int pos, int *rc, int drop_it) {
    char *cache[MAX_CACHE];
    char header[MAX_HEADER] = { '\0' };
    int icache = 0;
    char buffer[OS_MAXSTR];
    char *id;
    char *p;
    size_t z;
    long offset = ftell(logff[pos].fp);

    if (offset < 0) {
        merror(FTELL_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
        return NULL;
    }

    *rc = 0;

    if (logff[pos].skip_to_nl) {
        if (logr_fdrain_to_newline(pos, drop_it)) {
            logff[pos].skip_to_nl = 0;
        } else {
            return NULL;
        }
    }

    while (logr_fgets(buffer, OS_MAXSTR, pos, drop_it)) {
        if ((p = strchr(buffer, '\n')))
            *p = '\0';
        else {
            if (strlen(buffer) == OS_MAXSTR - 1) {
                // Message too large, discard line
                while (logr_fgets(buffer, OS_MAXSTR, pos, drop_it) &&
                       !strchr(buffer, '\n')) {
                }
                /* Budget or EOF mid-discard: finish through newline next visit. */
                if (!strchr(buffer, '\n')) {
                    logff[pos].skip_to_nl = 1;
                }
            } else {
                debug1("%s: Message not complete. Trying again: '%s'", ARGV0, buffer);

                if (fseek(logff[pos].fp, offset, SEEK_SET) < 0) {
                    merror(FSEEK_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
                    break;
                }
            }

            break;
        }

        // Extract header: "type=\.* msg=audit(\d+.\d+:\d+):"

        if (strncmp(buffer, "type=", 5) || !((id = strstr(buffer + 5, "msg=audit(")) && (p = strstr(id += 10, "): ")))) {
            merror("%s: ERROR: discarding audit message because of invalid syntax", ARGV0);
            break;
        }

        z = p - id;

        if (strncmp(id, header, z)) {
            // Current message belongs to another event: send cached messages
            if (icache > 0)
                audit_send_msg(cache, icache, logff[pos].file, drop_it);

            // Store current event
            *cache = strdup(buffer);
            icache = 1;
            strncpy(header, id, z < MAX_HEADER ? z : MAX_HEADER - 1);
        } else {
            // The header is the same: store
            if (icache == MAX_CACHE)
                merror("%s: ERROR: discarding audit message because cache is full", ARGV0);
            else
                cache[icache++] = strdup(buffer);
        }

        offset = ftell(logff[pos].fp);
        if (offset < 0) {
            merror(FTELL_ERROR, ARGV0, logff[pos].file, errno, strerror(errno));
            break;
        }
    }

    /* Same as EOF: forward what is cached. Rewinding an event larger than
     * max_lines would stall the file forever. */
    if (icache > 0)
        audit_send_msg(cache, icache, logff[pos].file, drop_it);

    return NULL;
}
