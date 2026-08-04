/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "ar.h"

/* Case-insensitive compare without relying on strcasecmp (Windows). */
static int ar_token_eq(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static int ar_is_separator(char c)
{
    return (c == ',' || isspace((unsigned char)c));
}

const char *ar_pick_username(const char *dstuser, const char *srcuser)
{
    if (dstuser && dstuser[0] && strcmp(dstuser, "-") != 0) {
        return dstuser;
    }

    if (srcuser && srcuser[0] && strcmp(srcuser, "-") != 0) {
        return srcuser;
    }

    return NULL;
}

int ar_parse_expect(const char *expect_str)
{
    int expect = 0;
    char *copy;
    char *cursor;
    char *tok;
    size_t len;

    if (!expect_str || !*expect_str) {
        return 0;
    }

    len = strlen(expect_str);
    copy = (char *)malloc(len + 1);
    if (!copy) {
        return 0;
    }
    memcpy(copy, expect_str, len + 1);

    /* Split on commas and/or whitespace so both
     * "srcip, username" and "srcip username" work. */
    cursor = copy;
    while (*cursor) {
        while (*cursor && ar_is_separator(*cursor)) {
            cursor++;
        }
        if (!*cursor) {
            break;
        }

        tok = cursor;
        while (*cursor && !ar_is_separator(*cursor)) {
            cursor++;
        }
        if (*cursor) {
            *cursor++ = '\0';
        }

        if (ar_token_eq(tok, "user") || ar_token_eq(tok, "username")) {
            expect |= USERNAME;
        } else if (ar_token_eq(tok, "srcip")) {
            expect |= SRCIP;
        } else if (ar_token_eq(tok, "filename")) {
            expect |= FILENAME;
        }
        /* Unknown tokens (e.g. legacy "hostname") are ignored. */
    }

    free(copy);
    return expect;
}
