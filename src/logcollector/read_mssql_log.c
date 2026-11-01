/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read MS SQL logs */

#include "shared.h"
#include "logcollector.h"


/* Send MS SQL message and check the return code */
static void __send_mssql_msg(int pos, int drop_it, char *buffer)
{
    debug2("%s: DEBUG: Reading MSSQL message: '%s'", ARGV0, buffer);
    if (drop_it == 0) {
        if (SendMSG(logr_queue, buffer, logff[pos].file, LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND, ARGV0);
            if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }
        }
    }
}

/* Read MS SQL log files */
void *read_mssql_log(int pos, int *rc, int drop_it)
{
    size_t str_len = 0;
    int need_clear = 0;
    int clear_was_full = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    fpos_t fp_pos;
    fpos_t buffer_start;
    int have_buffer_start = 0;
    int wait_more = 0;

    /* Zero buffer and str */
    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Finish discarding an over-long line that hit EOF on the previous poll
     * (ANT-2026-9HSM6MA8). */
    if (logff[pos].skip_to_nl) {
        if (logr_fdrain_to_newline(pos, drop_it)) {
            logff[pos].skip_to_nl = 0;
        } else {
            return (NULL);
        }
    }

    /* Get new entry */
    for (;;) {
        fgetpos(logff[pos].fp, &fp_pos);
        if (logr_fgets(str, OS_MAXSTR - OS_LOG_HEADER, pos, drop_it) == NULL) {
            /* Do not rewind over a mid-line discard; skip_to_nl resumes it. */
            if (logr_budget_exhausted() && have_buffer_start &&
                    !(need_clear && clear_was_full)) {
                fsetpos(logff[pos].fp, &buffer_start);
                wait_more = 1;
            }
            break;
        }
        /* Get buffer size */
        str_len = strlen(str);

        /* Check str_len size. Very useless, but just to make sure */
        if (str_len >= sizeof(buffer) - 2) {
            str_len = sizeof(buffer) - 10;
        }

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need clear is set, we just get the line and ignore it */
            if (need_clear) {
                need_clear = 0;
                clear_was_full = 0;
                continue;
            }
        } else if (need_clear) {
            /* Still in the middle of the line being ignored */
            continue;
        } else if (strlen(str) == (size_t)(OS_MAXSTR - OS_LOG_HEADER - 1)) {
            need_clear = 1;
            clear_was_full = 1;
        } else {
            /* Incomplete line: rewind to the open record (or this line). */
            if (have_buffer_start) {
                fsetpos(logff[pos].fp, &buffer_start);
                buffer[0] = '\0';
                have_buffer_start = 0;
            } else {
                fsetpos(logff[pos].fp, &fp_pos);
            }
            wait_more = 1;
            break;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on windows) */
        if (str_len <= 1) {
            continue;
        }

        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            continue;
        }
#endif

        /* MS SQL messages have the following formats:
         * 2009-03-25 04:47:30.01 Server
         * 2003-10-09 00:00:06.68 sys1
         * 2009-02-06 11:48:59     Server
         */
        if ((str_len > 19) &&
                (str[4] == '-') &&
                (str[7] == '-') &&
                (str[10] == ' ') &&
                (str[13] == ':') &&
                (str[16] == ':') &&
                isdigit((int)str[0]) &&
                isdigit((int)str[1]) &&
                isdigit((int)str[2]) &&
                isdigit((int)str[3])) {

            /* If the saved message is empty, set it and continue */
            if (buffer[0] == '\0') {
                strncpy(buffer, str, OS_MAXSTR);
                buffer_start = fp_pos;
                have_buffer_start = 1;
                continue;
            }

            /* If not, send the saved one and store the new one for later */
            else {
                __send_mssql_msg(pos, drop_it, buffer);

                /* Store current one at the buffer */
                strncpy(buffer, str, OS_MAXSTR);
                buffer_start = fp_pos;
                have_buffer_start = 1;
            }
        }

        /* Query logs can be in multiple lines
         * They always start with a tab in the additional lines
         */
        else if ((str_len > 2) && (buffer[0] != '\0')) {
            /* Size of the buffer */
            size_t buffer_len = strlen(buffer);

            p = str;

            /* Remove extra spaces and tabs */
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Add additional message to the saved buffer */
            if (sizeof(buffer) - buffer_len > str_len + 256) {
                /* Here we make sure that the size of the buffer
                 * minus what was used (strlen) is greater than
                 * the length of the received message.
                 */
                buffer[buffer_len] = ' ';
                buffer[buffer_len + 1] = '\0';
                strncat(buffer, str, OS_MAXSTR);
            }
        }

        continue;
    }

    /* Send whatever is stored (unless waiting for more of an open record). */
    if (!wait_more && buffer[0] != '\0') {
        __send_mssql_msg(pos, drop_it, buffer);
    }

    if (need_clear && clear_was_full) {
        logff[pos].skip_to_nl = 1;
    }

    return (NULL);
}

