/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ar.h"

/* Match OS_SIZE_1024 without pulling shared.h (ar_expect_test links this file alone). */
#define AR_REMOTE_HDR_BUFSZ 1025


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

int ar_safe_argument(const char *value)
{
    const unsigned char *p;

    if (value == NULL || value[0] == '\0' || value[0] == '-') {
        return 0;
    }
    if (strcmp(value, ".") == 0 || strcmp(value, "..") == 0) {
        return 0;
    }

    for (p = (const unsigned char *)value; *p != '\0'; p++) {
        if ((*p >= '0' && *p <= '9') ||
                (*p >= 'A' && *p <= 'Z') ||
                (*p >= 'a' && *p <= 'z') ||
                *p == '.' || *p == ':' || *p == '-' || *p == '_' || *p == '@') {
            continue;
        }
        return 0;
    }

    return 1;
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

int OS_AR_FormatRemoteHdr(const char *location, char f_all, char f_remote,
                          char f_specific, char **out_hdr)
{
    char buf[AR_REMOTE_HDR_BUFSZ];
    char *hdr;
    int n;

    if (!location || !out_hdr) {
        return -1;
    }
    *out_hdr = NULL;

    /* remoted splits on spaces and reads the targets immediately after the
     * source field. Only the manager-written "(name) ip" (cut at "->") may
     * go there; text after "->" is agent- or log-controlled and may contain
     * spaces (ANT-2026-PMMTS4QR). Manager-local events use a constant []. */
    if (location[0] == '(') {
        const char *source_end = strstr(location, "->");

        if (!source_end) {
            return -1;
        }

        n = snprintf(buf, sizeof(buf), "%.*s %c%c%c",
                     (int)(source_end - location), location,
                     f_all, f_remote, f_specific);
    } else {
        n = snprintf(buf, sizeof(buf), "(local_source) [] %c%c%c",
                     f_all, f_remote, f_specific);
    }

    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return -1;
    }

    hdr = malloc((size_t)n + 1);
    if (!hdr) {
        return -1;
    }
    memcpy(hdr, buf, (size_t)n + 1);
    *out_hdr = hdr;
    return 0;
}
