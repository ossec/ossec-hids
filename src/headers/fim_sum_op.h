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
 * (size:perm:uid:gid:md5:sha1[:sha256][:attrs]).
 * Legacy: 6 flag chars. Current: 7 (sha256). With attrs: 8 flag chars. */
int fim_sum_data_offset(const char *hash_entry);

/* Compare two sum strings (size:perm:uid:gid:md5:sha1[:sha256][:attrs]).
 * Returns 1 if they differ in a "real" way (size/perm/owner/group/attrs, or a
 * hash where neither side is the xxx placeholder). Returns 0 if equal or the
 * only hash differences involve placeholders (#1590/#1704). */
int fim_sum_has_real_change(const char *old_sum, const char *new_sum);

/* Format Windows GetFileAttributes bits into a comma-separated name list
 * (e.g. "ARCHIVE, HIDDEN"). Returns buf. Unknown bits are omitted; if none
 * match, writes "NONE". */
char *fim_win_attrs_str(unsigned int attrs, char *buf, size_t buflen);

#endif
