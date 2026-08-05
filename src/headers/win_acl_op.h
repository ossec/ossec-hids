/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN_ACL_OP_H
#define WIN_ACL_OP_H

#include <stddef.h>

/* Sentinel labels digested via OS_MD5_Str("NODACL") / OS_MD5_Str("NULLDACL"). */

#define FIM_ACE_ALLOW 0
#define FIM_ACE_DENY  1

#define FIM_ACL_NORMAL    0
#define FIM_ACL_NODACL    1
#define FIM_ACL_NULLDACL  2

/* Portable inheritance bits (match Windows ACE flags). */
#define FIM_ACE_OI  0x01
#define FIM_ACE_CI  0x02
#define FIM_ACE_NP  0x04
#define FIM_ACE_IO  0x08
#define FIM_ACE_ID  0x10

typedef struct fim_ace {
    char sid[192];         /* enough for max canonical SID string + NUL */
    int type;              /* FIM_ACE_ALLOW / FIM_ACE_DENY */
    unsigned int flags;    /* inheritance bits */
    unsigned int mask;
    unsigned int ord;      /* original DACL order (included in digest) */
} fim_ace_t;

typedef struct fim_acl {
    fim_ace_t *aces;
    size_t count;
    int special;           /* FIM_ACL_NORMAL / NODACL / NULLDACL */
} fim_acl_t;

void fim_acl_free(fim_acl_t *acl);
void fim_acl_sort(fim_acl_t *acl);

/* Read NTFS DACL for path. Returns 0 on success. Non-Windows: returns -1. */
int fim_win_acl_read(const char *path, fim_acl_t *out);

/* MD5 hex (33 bytes) of canonical ACE list / sentinel. Returns 0 on success. */
int fim_win_acl_digest(const fim_acl_t *acl, char *md5_hex33);

/* Format full matrix into buf. Returns bytes written (may truncate). */
int fim_win_acl_format(const fim_acl_t *acl, char *buf, size_t buflen);

/* ACE-level Added/Removed/Modified diff into buf. */
int fim_win_acl_diff(const fim_acl_t *old_acl, const fim_acl_t *new_acl,
                     char *buf, size_t buflen);

/* Parse canonical snapshot text (from local cache) into acl. Returns 0 on success. */
int fim_win_acl_parse_snapshot(const char *text, fim_acl_t *out);

/* Write canonical snapshot (SID-stable, for cache + digest input). */
int fim_win_acl_snapshot(const fim_acl_t *acl, char *buf, size_t buflen);

/* Build human-readable ACL change text from local-cache / c_sum entries
 * that may include a "\\n" + snapshot after the sum. Returns bytes written,
 * 0 if nothing to report, or -1 on error. */
int fim_win_acl_change_text(const char *old_sum_entry, const char *new_sum_entry,
                            char *buf, size_t buflen);

#endif
