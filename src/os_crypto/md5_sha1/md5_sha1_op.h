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

#ifdef LIBSODIUM_ENABLED
#include <sodium.h>
#endif  //LIBSODIUM_ENABLED

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"

int OS_MD5_SHA1_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, int mode) __attribute((nonnull(1, 3, 4)));

#endif

#ifdef LIBSODIUM_ENABLED

struct hash_output {
    // What are we looking for?
    int check_md5;
    int check_sha1;
    int check_sha256;
    int check_generic;

    // Here's where we put it.
    char md5output[37];
    char sha1output[70];
    char genericoutput[138];
    char sha256output[crypto_hash_sha256_BYTES + 7];
};

int OS_Hash_File(const char *fname, const char *prefilter_cmd, struct hash_output *file_output, int mode);
#endif

