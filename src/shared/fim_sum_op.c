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
#include <stdlib.h>

#include "fim_sum_op.h"

/* Match Windows FILE_ATTRIBUTE_* values so this builds on non-Windows too. */
#define FIM_ATTR_READONLY              0x00000001
#define FIM_ATTR_HIDDEN                0x00000002
#define FIM_ATTR_SYSTEM                0x00000004
#define FIM_ATTR_DIRECTORY             0x00000010
#define FIM_ATTR_ARCHIVE               0x00000020
#define FIM_ATTR_DEVICE                0x00000040
#define FIM_ATTR_NORMAL                0x00000080
#define FIM_ATTR_TEMPORARY             0x00000100
#define FIM_ATTR_SPARSE_FILE           0x00000200
#define FIM_ATTR_REPARSE_POINT         0x00000400
#define FIM_ATTR_COMPRESSED            0x00000800
#define FIM_ATTR_OFFLINE               0x00001000
#define FIM_ATTR_NOT_CONTENT_INDEXED   0x00002000
#define FIM_ATTR_ENCRYPTED             0x00004000

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
    size_t len;

    if (!hash_entry) {
        return (6);
    }

    len = strlen(hash_entry);
    if (len < 7) {
        return (6);
    }

    /* Legacy: flags[6] starts the size digits. */
    if (hash_entry[6] != '+' && hash_entry[6] != '-') {
        return (6);
    }

    /* With ACL: flags[8] is '+' or '-' before size. */
    if (len >= 9 && (hash_entry[8] == '+' || hash_entry[8] == '-')) {
        return (9);
    }

    /* With attrs: flags[7] is '+' or '-' before size. */
    if (len >= 8 && (hash_entry[7] == '+' || hash_entry[7] == '-')) {
        return (8);
    }

    /* Current: 7 flag chars (includes sha256 enable flag). */
    return (7);
}

size_t fim_sum_data_len(const char *sum_and_maybe_snapshot)
{
    const char *nl;

    if (!sum_and_maybe_snapshot) {
        return (0);
    }
    nl = strchr(sum_and_maybe_snapshot, '\n');
    if (nl) {
        return (size_t)(nl - sum_and_maybe_snapshot);
    }
    return (strlen(sum_and_maybe_snapshot));
}

int fim_sum_equal(const char *a, const char *b)
{
    size_t alen, blen;

    if (!a || !b) {
        return (0);
    }
    alen = fim_sum_data_len(a);
    blen = fim_sum_data_len(b);
    if (alen != blen) {
        return (0);
    }
    return (strncmp(a, b, alen) == 0);
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
    char old_buf[1024];
    char new_buf[1024];
    char *of[10];
    char *nf[10];
    int oc, nc, i;
    size_t olen, nlen;

    if (!old_sum || !new_sum) {
        return (1);
    }

    if (strcmp(old_sum, new_sum) == 0) {
        return (0);
    }

    olen = fim_sum_data_len(old_sum);
    nlen = fim_sum_data_len(new_sum);
    if (olen >= sizeof(old_buf) || nlen >= sizeof(new_buf)) {
        return (1);
    }

    memcpy(old_buf, old_sum, olen);
    old_buf[olen] = '\0';
    memcpy(new_buf, new_sum, nlen);
    new_buf[nlen] = '\0';

    if (strcmp(old_buf, new_buf) == 0) {
        return (0);
    }

    oc = fim_split_sum(old_buf, of, 10);
    nc = fim_split_sum(new_buf, nf, 10);
    if (oc < 6 || nc < 6) {
        return (1);
    }

    /* size, perm, uid, gid */
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

    /* Optional attrs (index 7) */
    if (oc >= 8 && nc >= 8) {
        if (strcmp(of[7], nf[7]) != 0) {
            return (1);
        }
    } else if (oc >= 8 || nc >= 8) {
        return (1);
    }

    /* Optional ACL digest (index 8) */
    if (oc >= 9 && nc >= 9) {
        if (strcmp(of[8], nf[8]) != 0) {
            return (1);
        }
    } else if (oc >= 9 || nc >= 9) {
        return (1);
    }

    return (0);
}

int fim_sum_get_field(const char *sum, int index, char *buf, size_t buflen)
{
    char tmp[1024];
    char *fields[10];
    size_t nlen;
    int n;
    int written;

    if (!sum || !buf || buflen == 0 || index < 0) {
        return (-1);
    }
    buf[0] = '\0';
    nlen = fim_sum_data_len(sum);
    if (nlen == 0 || nlen >= sizeof(tmp)) {
        return (-1);
    }
    memcpy(tmp, sum, nlen);
    tmp[nlen] = '\0';
    n = fim_split_sum(tmp, fields, 10);
    if (index >= n) {
        return (-1);
    }
    written = snprintf(buf, buflen, "%s", fields[index]);
    if (written < 0 || (size_t)written >= buflen) {
        buf[0] = '\0';
        return (-1);
    }
    return (0);
}

char *fim_win_attrs_str(unsigned int attrs, char *buf, size_t buflen)
{
    static const struct {
        unsigned int bit;
        const char *name;
    } table[] = {
        { FIM_ATTR_READONLY,            "READONLY" },
        { FIM_ATTR_HIDDEN,              "HIDDEN" },
        { FIM_ATTR_SYSTEM,              "SYSTEM" },
        { FIM_ATTR_DIRECTORY,           "DIRECTORY" },
        { FIM_ATTR_ARCHIVE,             "ARCHIVE" },
        { FIM_ATTR_DEVICE,              "DEVICE" },
        { FIM_ATTR_NORMAL,              "NORMAL" },
        { FIM_ATTR_TEMPORARY,           "TEMPORARY" },
        { FIM_ATTR_SPARSE_FILE,         "SPARSE" },
        { FIM_ATTR_REPARSE_POINT,       "REPARSE_POINT" },
        { FIM_ATTR_COMPRESSED,          "COMPRESSED" },
        { FIM_ATTR_OFFLINE,             "OFFLINE" },
        { FIM_ATTR_NOT_CONTENT_INDEXED, "NOT_CONTENT_INDEXED" },
        { FIM_ATTR_ENCRYPTED,           "ENCRYPTED" },
        { 0, NULL }
    };
    size_t used = 0;
    int i;
    int any = 0;

    if (!buf || buflen == 0) {
        return (buf);
    }

    buf[0] = '\0';
    for (i = 0; table[i].name != NULL; i++) {
        size_t nlen;

        if ((attrs & table[i].bit) == 0) {
            continue;
        }
        nlen = strlen(table[i].name);
        if (any) {
            if (used + 2 >= buflen) {
                break;
            }
            buf[used++] = ',';
            buf[used++] = ' ';
            buf[used] = '\0';
        }
        if (used + nlen >= buflen) {
            break;
        }
        memcpy(buf + used, table[i].name, nlen + 1);
        used += nlen;
        any = 1;
    }

    if (!any) {
        snprintf(buf, buflen, "NONE");
    }

    return (buf);
}
