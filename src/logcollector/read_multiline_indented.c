/* Copyright (C) 2019, Semper Victus LLC
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read indentend multi line logs */

#include "shared.h"
#include "logcollector.h"


/* Read multi line indented log files */
void *read_multiline_indented(int pos, int *rc, int drop_it) {
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
        if (fdrain_to_newline(logff[pos].fp)) {
            logff[pos].skip_to_nl = 0;
        } else {
            return (NULL);
        }
    }

    /* Get new entry */
    for (;;) {
        fgetpos(logff[pos].fp, &fp_pos);
        if (fgets_no_nul(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) == NULL) {
            break;
        }

        /* Get buffer size */
        str_len = strlen(str);

        /* Check str_len size. Very useless, but just to make sure.. */
        if (str_len >= sizeof(buffer) - 2) {
            str_len = sizeof(buffer) - 10;
        }

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need_clear is set, we just get the line and ignore it */
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
#endif
        /* Look for empty string */
        if ((str_len <= 1) || (str[0] == '\r')) {
            /* Send existing data if any in buffer */
            if (buffer[0] != '\0') {
              if (drop_it == 0 && SendMSG(logr_queue, buffer, logff[pos].file, LOCALFILE_MQ) < 0) {
                  merror(QUEUE_SEND, ARGV0);
                  if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                      ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                  }
              }
              buffer[0] = '\0';
            }
            continue;
        }

        /* Look for lines starting with indents */
        if ((str_len > 2) && (buffer[0] != '\0') &&
                 ((str[0] == ' ') || (str[0] == '\t'))) {
            /* Size of the buffer */
            size_t buffer_len = strlen(buffer);

            p = str + 1;

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
                strncat(buffer, str, str_len + 3);
            }
        /* Look for lines not starting with indents */
        } else if ((str[0] != ' ') || (str[0] != '\t')) {
            /* Flush previous messages */
            if (buffer[0] != '\0') {
              if (drop_it == 0 && SendMSG(logr_queue, buffer, logff[pos].file, LOCALFILE_MQ) < 0) {
                  merror(QUEUE_SEND, ARGV0);
                  if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                      ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                  }
              }
              buffer[0] = '\0';
            }
            strncpy(buffer, str, str_len + 2);
            buffer_start = fp_pos;
            have_buffer_start = 1;
            continue;
       /* Error handling for buffer[0] being '\0' when indents are present */
       } else {
           // messages or retries
       }

    }

    /* Send whatever is stored (unless waiting for more of an open record). */
    if (!wait_more && buffer[0] != '\0') {
      if (drop_it == 0 && SendMSG(logr_queue, buffer, logff[pos].file, LOCALFILE_MQ) < 0) {
          merror(QUEUE_SEND, ARGV0);
          if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
              ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
          }
      }
    }

    if (need_clear && clear_was_full) {
        logff[pos].skip_to_nl = 1;
    }

    return (NULL);
}
