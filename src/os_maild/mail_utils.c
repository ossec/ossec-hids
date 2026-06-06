/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

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
