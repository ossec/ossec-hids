/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FIM_SUM_OP_H
#define FIM_SUM_OP_H

#include <stddef.h>

/* "xxx" is the syscheck placeholder for a hash that was not computed. */
int fim_hash_is_placeholder(const char *hash);

/* Offset from the start of a local syscheck.fp hash entry to the sum data
 * (size:perm:uid:gid:md5:sha1[:sha256][:attrs][:acl]).
 * Legacy: 6 flag chars. Current: 7 (sha256). Attrs: 8. ACL: 9. */
int fim_sum_data_offset(const char *hash_entry);

/* Compare sum strings including optional attrs (index 7) and acl digest (8).
 * Ignores anything after the first newline (local ACL snapshot). */
int fim_sum_has_real_change(const char *old_sum, const char *new_sum);

/* 1 if sum portions (before newline) are identical. */
int fim_sum_equal(const char *a, const char *b);

/* Format Windows GetFileAttributes bits into a comma-separated name list
 * (e.g. "ARCHIVE, HIDDEN"). Returns buf. Unknown bits are omitted; if none
 * match, writes "NONE". */
char *fim_win_attrs_str(unsigned int attrs, char *buf, size_t buflen);

/* Length of sum data in a local cache entry (stops at newline ACL snapshot). */
size_t fim_sum_data_len(const char *sum_and_maybe_snapshot);

/* Copy 0-based sum field into buf (stops at newline). Returns 0 on success. */
int fim_sum_get_field(const char *sum, int index, char *buf, size_t buflen);

#endif
