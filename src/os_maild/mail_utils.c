/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <string.h>

#include "mail_utils.h"

int mail_address_has_crlf(const char *addr)
{
    if (!addr) {
        return (0);
    }

    return (strchr(addr, '\r') != NULL || strchr(addr, '\n') != NULL);
}

void mail_sanitize_header_value(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;

    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    while (src[0] && j < dst_size - 1) {
        if (src[0] != '\r' && src[0] != '\n') {
            dst[j++] = src[0];
        }
        src++;
    }
    dst[j] = '\0';
}

int mail_append_header_line(char *buf, size_t cap, const char *line)
{
    size_t used;
    size_t room;
    int n;

    if (!buf || cap == 0 || !line) {
        return (-1);
    }

    used = strlen(buf);
    if (used >= cap - 1) {
        return (-1);
    }

    room = cap - used - 1;
    n = snprintf(buf + used, room + 1, "%s", line);
    if (n < 0 || (size_t)n > room) {
        buf[cap - 1] = '\0';
        return (-1);
    }

    return (0);
}

int mail_has_cc_recipients(char **to, int sms_only)
{
    if (sms_only || !to) {
        return (0);
    }

    return (to[1] != NULL);
}

int mail_safe_envelope_value(const char *src, char *dst, size_t dst_size)
{
    if (!dst || dst_size == 0) {
        return (-1);
    }

    if (!src || mail_address_has_crlf(src)) {
        dst[0] = '\0';
        return (-1);
    }

    mail_sanitize_header_value(src, dst, dst_size);
    return (dst[0] != '\0') ? 0 : -1;
}
