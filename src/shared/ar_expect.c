/* Copyright (C) 2026 Atomicorp LLC
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

/* Trim leading/trailing whitespace in place; return start of token. */
static char *ar_trim_token(char *tok)
{
    char *end;

    if (!tok) {
        return tok;
    }

    while (*tok && isspace((unsigned char)*tok)) {
        tok++;
    }

    if (!*tok) {
        return tok;
    }

    end = tok + strlen(tok);
    while (end > tok && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }

    return tok;
}

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

    cursor = copy;
    while (cursor && *cursor) {
        char *comma = strchr(cursor, ',');
        if (comma) {
            *comma = '\0';
            tok = cursor;
            cursor = comma + 1;
        } else {
            tok = cursor;
            cursor = NULL;
        }

        tok = ar_trim_token(tok);
        if (!*tok) {
            continue;
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
