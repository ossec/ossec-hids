/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * One-pass checksum of a monitored file, bounded by syscheck.file_max_size
 * so a sparse file cannot stall the daemon (ANT-2026-J8XF7LCX).
 */

#include <errno.h>
#include <string.h>

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

/* 0 hashed, 1 over the size limit (sums left as xxx, file still reported),
 * -1 the file could not be read. */
int c_hash_file(const char *file_name, const struct stat *st,
                os_md5 mf_sum, os_sha1 sf_sum, os_sha256 sha256_sum)
{
    strncpy(mf_sum, "xxx", 4);
    strncpy(sf_sum, "xxx", 4);
    strncpy(sha256_sum, "xxx", 4);

    if (syscheck.file_max_size > 0 && st != NULL && st->st_size > 0 &&
            (size_t)st->st_size > syscheck.file_max_size) {
        c_read_warn("%s: WARN: File '%s' is over the checksum size limit.",
                    ARGV0, file_name);
        return (1);
    }

    if (OS_MD5_SHA1_SHA256_File(file_name, mf_sum, sf_sum, sha256_sum,
                                OS_BINARY, syscheck.file_max_size) < 0) {
        strncpy(mf_sum, "xxx", 4);
        strncpy(sf_sum, "xxx", 4);
        strncpy(sha256_sum, "xxx", 4);
        if (errno == EFBIG) {
            c_read_warn("%s: WARN: File '%s' grew past the checksum size limit.",
                        ARGV0, file_name);
            return (1);
        }
        return (-1);
    }
    return (0);
}
