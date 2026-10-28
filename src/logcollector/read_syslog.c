/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the syslog */

#include "shared.h"
#include "logcollector.h"

/* Max payload bytes one read can return (fgets-equivalent size minus NUL). */
#define SYSLOG_CHUNK (OS_MAXSTR - OS_LOG_HEADER - 1)

/* Same contract as fgets(), but embedded NULs from the file become spaces so
 * the only NUL in the buffer is the terminator (issue #913). Returns the
 * number of bytes stored (not counting the terminator), or 0 on EOF/empty.
 * Byte count is taken from the getc loop so Windows text-mode ftell cannot
 * mis-count CRLF translations (ANT-2026-RNCE3SO7 blend). */
static size_t read_syslog_line(char *str, size_t max_payload, FILE *fp)
{
    int c;
    char *p = str;
    size_t left = max_payload;

    while (left > 0 && (c = getc(fp)) != EOF) {
        *p++ = (c == '\0') ? ' ' : (char)c;
        left--;
        if (c == '\n') {
            break;
        }
    }
    *p = '\0';

    return (size_t)(p - str);
}

/* Discard through the next newline (or EOF). Returns 1 if a newline was
 * found, 0 if EOF ended the drain early. */
static int drain_to_newline(FILE *fp)
{
    char str[OS_MAXSTR + 1];
    size_t rbytes;

    str[OS_MAXSTR] = '\0';

    while ((rbytes = read_syslog_line(str, (size_t)OS_MAXSTR - 2, fp)) > 0) {
        if (str[rbytes - 1] == '\n') {
            return 1;
        }
    }
    return 0;
}

/* Read syslog files */
void *read_syslog(int pos, int *rc, int drop_it)
{
    int __ms = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    fpos_t fp_pos;
    size_t rbytes;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Finish discarding an over-long line that hit EOF on the previous poll
     * so its remainder cannot become a forged standalone event
     * (ANT-2026-RNCE3SO7). */
    if (logff[pos].skip_to_nl) {
        if (drain_to_newline(logff[pos].fp)) {
            logff[pos].skip_to_nl = 0;
        } else {
            /* Still no newline; try again next poll. */
            return (NULL);
        }
    }

    /* Get initial file location */
    fgetpos(logff[pos].fp, &fp_pos);

    while ((rbytes = read_syslog_line(str, (size_t)SYSLOG_CHUNK, logff[pos].fp)) > 0) {
        /* Complete line */
        if (str[rbytes - 1] == '\n') {
            str[rbytes - 1] = '\0';
            __ms = 0;
        }
        /* Full buffer without newline: over-long byte count. */
        else if (rbytes == (size_t)SYSLOG_CHUNK) {
            __ms = 1;
        } else {
            /* Incomplete: newline not written yet. Rewind and wait. */
            debug1("%s: Message not complete. Trying again: '%s'", ARGV0, str);
            fsetpos(logff[pos].fp, &fp_pos);
            break;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Comment / short-line filters only for complete lines. An over-long
         * chunk that happens to look like a comment must still be drained. */
        if (!__ms) {
            if (strlen(str) <= 2) {
                fgetpos(logff[pos].fp, &fp_pos);
                continue;
            }
            if (str[0] == '#') {
                fgetpos(logff[pos].fp, &fp_pos);
                continue;
            }
        }
#else
        (void)p;
#endif

        debug2("%s: DEBUG: Reading syslog message: '%s'", ARGV0, str);

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSG(logr_queue, str, logff[pos].file,
                        LOCALFILE_MQ) < 0) {
                merror(QUEUE_SEND, ARGV0);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }

        /* Incorrect message size: discard through the real newline. */
        if (__ms) {
#define OUTSIZE 4096
            char buf[OUTSIZE + 1];
            buf[OUTSIZE] = '\0';
            snprintf(buf, OUTSIZE, "%s", str);
            merror("%s: Large message size(length=%d): '%s...'", ARGV0,
                   (int)strlen(str), buf);
            if (!drain_to_newline(logff[pos].fp)) {
                /* Remainder still being written; skip it on the next poll. */
                logff[pos].skip_to_nl = 1;
                break;
            }
            __ms = 0;
        }

        fgetpos(logff[pos].fp, &fp_pos);
        continue;
    }

    return (NULL);
}
