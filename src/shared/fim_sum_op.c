/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <string.h>
#include <stdlib.h>

#include "fim_sum_op.h"

int fim_hash_is_placeholder(const char *hash)
{
    size_t len;

    if (!hash || !*hash) {
        return (1);
    }

    /* Placeholder is exactly "xxx" (field may continue with ':' in a sum). */
    len = strlen(hash);
    if (len >= 3 && hash[0] == 'x' && hash[1] == 'x' && hash[2] == 'x' &&
            (len == 3 || hash[3] == ':')) {
        return (1);
    }

    return (0);
}

int fim_sum_data_offset(const char *hash_entry)
{
    if (!hash_entry || strlen(hash_entry) < 7) {
        return (6);
    }

    /* New format: flags[6] is '+' or '-' for sha256. Legacy: flags[6] starts size. */
    if (hash_entry[6] == '+' || hash_entry[6] == '-') {
        return (7);
    }

    return (6);
}

/* Split "a:b:c:..." into up to max_fields pointers into a mutable copy. */
static int fim_split_sum(char *buf, char **fields, int max_fields)
{
    int n = 0;
    char *p = buf;

    if (!buf || !fields || max_fields <= 0) {
        return (0);
    }

    fields[n++] = p;
    while (*p && n < max_fields) {
        if (*p == ':') {
            *p = '\0';
            p++;
            fields[n++] = p;
            continue;
        }
        p++;
    }

    return (n);
}

int fim_sum_has_real_change(const char *old_sum, const char *new_sum)
{
    char old_buf[512];
    char new_buf[512];
    char *of[8];
    char *nf[8];
    int oc, nc, i;
    size_t olen, nlen;

    if (!old_sum || !new_sum) {
        return (1);
    }

    if (strcmp(old_sum, new_sum) == 0) {
        return (0);
    }

    olen = strlen(old_sum);
    nlen = strlen(new_sum);
    if (olen >= sizeof(old_buf) || nlen >= sizeof(new_buf)) {
        /* Oversized: fall back to strict compare already failed above */
        return (1);
    }

    memcpy(old_buf, old_sum, olen + 1);
    memcpy(new_buf, new_sum, nlen + 1);

    oc = fim_split_sum(old_buf, of, 8);
    nc = fim_split_sum(new_buf, nf, 8);
    if (oc < 6 || nc < 6) {
        return (1);
    }

    /* size, perm, uid, gid — always meaningful when they differ */
    for (i = 0; i < 4; i++) {
        if (strcmp(of[i], nf[i]) != 0) {
            return (1);
        }
    }

    /* md5, sha1, optional sha256 — ignore placeholder transitions */
    for (i = 4; i < oc && i < nc && i < 7; i++) {
        if (strcmp(of[i], nf[i]) == 0) {
            continue;
        }
        if (fim_hash_is_placeholder(of[i]) || fim_hash_is_placeholder(nf[i])) {
            continue;
        }
        return (1);
    }

    return (0);
}
