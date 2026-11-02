/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdbool.h>

#include "csyslogd.h"

/* Escape CEF messages according to the standards */
char *cefescape(const char *msg, const bool header)
{
    static char *buffer = NULL;
    const char *ptr;
    char *buffptr;
    size_t size;
    int needs_escape = 0;

    /* Recycle the buffer */
    if (buffer) {
        os_free(buffer);
        buffer = NULL;
    }

    /* Cleanup call */
    if (NULL == msg) {
        return NULL;
    }

    if (header && strchr(msg, '|')) {
        needs_escape = 1;
    }
    if (!header && strchr(msg, '=')) {
        needs_escape = 1;
    }
    if (strchr(msg, '\\') || strchr(msg, '\r') || strchr(msg, '\n')) {
        needs_escape = 1;
    }
    if (!needs_escape) {
        return (char *)msg;
    }

    /* Calculate the size of the escaped message
     *
     * In the header we replace \r and \n with a
     * space, so there's no change in size.
     */
    ptr = msg;
    size = 1;
    while (*ptr) {
        if (('\\' == *ptr) ||
            (header && ('|' == *ptr)) ||
            (!header && (
                ('=' == *ptr) ||
                ('\r' == *ptr) ||
                ('\n' == *ptr)
            )))
        {
            size += 2;
        } else {
            size += 1;
        }
        ptr++;
    }

    /* Allocate the new buffer and start escaping */
    buffer = (char*) malloc(size);
    buffer[size-1] = '\0';
    ptr = msg;
    buffptr = buffer;
    while (*ptr) {
        if ('\\' == *ptr) {
            *buffptr = '\\';
            *(buffptr + 1) = '\\';
            buffptr += 2;
        } else if ('\r' == *ptr) {
            *buffptr = header ? ' ' : '\\';
            buffptr++;
            if (!header) {
                *buffptr = 'r';
                buffptr++;
            }
        } else if ('\n' == *ptr) {
            *buffptr = header ? ' ' : '\\';
            buffptr++;
            if (!header) {
                *buffptr = 'n';
                buffptr++;
            }
        } else if (header && ('|' == *ptr)) {
            *buffptr = '\\';
            *(buffptr + 1) = '|';
            buffptr += 2;
        } else if (!header && ('=' == *ptr)) {
            *buffptr = '\\';
            *(buffptr + 1) = '=';
            buffptr += 2;
        } else {
            *buffptr = *ptr;
            buffptr++;
        }
        ptr++;
    }

    return buffer;
}

/* Escape Splunk key="value" fields: a double quote would end the value
 * early and turn the rest into further pairs, so quotes are removed
 * (as os_strip_char() used to do) and backslashes are doubled so a value
 * cannot escape its own closing quote. CR/LF become spaces so a UDP
 * syslog datagram cannot be split into further key=value lines.
 */
char *splunkescape(const char *msg)
{
    static char *buffer = NULL;
    const char *ptr;
    char *buffptr;

    /* Recycle the buffer */
    if (buffer) {
        os_free(buffer);
        buffer = NULL;
    }

    /* Cleanup call */
    if (NULL == msg) {
        return NULL;
    }

    if (!strchr(msg, '"') && !strchr(msg, '\\') &&
            !strchr(msg, '\r') && !strchr(msg, '\n')) {
        return (char *)msg;
    }

    /* Worst case every character is a backslash */
    os_calloc(2 * strlen(msg) + 1, sizeof(char), buffer);
    ptr = msg;
    buffptr = buffer;
    while (*ptr) {
        if ('\\' == *ptr) {
            *buffptr = '\\';
            *(buffptr + 1) = '\\';
            buffptr += 2;
        } else if ('\r' == *ptr || '\n' == *ptr) {
            *buffptr = ' ';
            buffptr++;
        } else if ('"' != *ptr) {
            *buffptr = *ptr;
            buffptr++;
        }
        ptr++;
    }
    *buffptr = '\0';

    return buffer;
}
