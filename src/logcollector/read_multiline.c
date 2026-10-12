/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"


/* Read multiline logs */
void *read_multiline(int pos, int *rc, int drop_it)
{
    int __ms = 0;
    int truncated = 0;
    int linecount;
    int linesgot = 0;
    size_t buffer_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    fpos_t fp_pos;

    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    linecount = atoi(logff[pos].logformat);

    /* Get initial file location */
    fgetpos(logff[pos].fp, &fp_pos);

    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) != NULL) {
        linesgot++;

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)) {
            /* Message size > maximum allowed */
            __ms = 1;
        } else {
            /* Message not complete. Return. */
            debug1("%s: Message not complete. Trying again: '%s'", ARGV0, str);
            fsetpos(logff[pos].fp, &fp_pos);
            break;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }
#endif

        debug2("%s: DEBUG: Reading message: '%s'", ARGV0, str);

        /* Append this line. buffer_size is a size_t, so
         * OS_MAXSTR - buffer_size - 2 wraps once the accumulated
         * text is near OS_MAXSTR and strncpy runs off the stack.
         * Copy only the bytes still free in buffer. __ms means the
         * physical line had no newline; do not set it here or the
         * drain below discards the next complete record.
         */
        buffer_size = strlen(buffer);
        if (buffer[0] != '\0' && buffer_size < sizeof(buffer) - 1) {
            buffer[buffer_size] = ' ';
            buffer_size++;
            buffer[buffer_size] = '\0';
        }

        if (buffer_size >= sizeof(buffer) - 1) {
            if (!truncated && !__ms) {
                merror("%s: Large message size: '%s'", ARGV0, str);
                truncated = 1;
            }
        } else {
            size_t room = sizeof(buffer) - buffer_size - 1;
            size_t str_len = strlen(str);

            if (str_len > room) {
                memcpy(buffer + buffer_size, str, room);
                buffer[buffer_size + room] = '\0';
                if (!__ms) {
                    merror("%s: Large message size: '%s'", ARGV0, str);
                }
                truncated = 1;
            } else {
                memcpy(buffer + buffer_size, str, str_len + 1);
            }
        }

        if (linesgot < linecount) {
            continue;
        }

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSG(logr_queue, buffer, logff[pos].file,
                        LOCALFILE_MQ) < 0) {
                merror(QUEUE_SEND, ARGV0);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }

        buffer[0] = '\0';
        truncated = 0;

        /* Incorrect message size. Only an unfinished physical line
         * leaves bytes in the file that have to be discarded.
         */
        if (__ms) {
            merror("%s: Large message size: '%s'", ARGV0, str);
            while (fgets(str, OS_MAXSTR - 2, logff[pos].fp) != NULL) {
                /* Get the last occurrence of \n */
                if ((p = strrchr(str, '\n')) != NULL) {
                    break;
                }
            }
            __ms = 0;
        }

        fgetpos(logff[pos].fp, &fp_pos);
        continue;
    }

    return (NULL);
}

