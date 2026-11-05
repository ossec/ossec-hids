/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __MD5SHA1_OP_H
#define __MD5SHA1_OP_H

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"

int OS_MD5_SHA1_File(const char *fname, os_md5 md5output, os_sha1 sha1output, int mode) __attribute((nonnull(1, 2, 3)));

#include "../sha256/sha256_op.h"

/* One read for MD5, SHA-1 and SHA-256. max_size is a byte cap (0 = none).
 * Returns -1 with errno EFBIG when the file is larger than max_size
 * (ANT-2026-J8XF7LCX). */
int OS_MD5_SHA1_SHA256_File(const char *fname, os_md5 md5output, os_sha1 sha1output,
                            os_sha256 sha256output, int mode, size_t max_size)
__attribute((nonnull(1, 2, 3, 4)));

#endif
