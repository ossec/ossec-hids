/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Field helpers for logcollector ossecalert forwarding (ANT-2026-8TB11KJO).
 */

#include <stdio.h>
#include <string.h>

#include "ossecalert_field.h"

void OS_OaCleanField(char *field)
{
    if (!field) {
        return;
    }

    while ((field = strchr(field, ';')) != NULL) {
        *field = ',';
    }
}

int OS_OaFormatTaggedField(char *dst, size_t dst_sz,
                           const char *tag, const char *value)
{
    int n;

    if (!dst || dst_sz < 8 || !tag || !value) {
        return (-1);
    }

    /* Bound the value so the closing ';' always fits in the historical
     * 255-byte snprintf used by read_ossecalert(). */
    n = snprintf(dst, dst_sz > 255 ? 255 : dst_sz, " %s: %.*s;",
                 tag, OA_FIELD_MAX, value);
    if (n < 0 || (size_t)n >= (dst_sz > 255 ? 255 : dst_sz)) {
        return (-1);
    }
    return (0);
}
