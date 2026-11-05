/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * One-pass checksum of a monitored file, bounded by syscheck.file_max_size
 * so a sparse file cannot stall the daemon (ANT-2026-J8XF7LCX).
 * Opens stay on the directory that was listed, or refuse a symlink below
 * a configured directory (ANT-2026-MBH20U16).
 */

#include <errno.h>
#include <string.h>

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

static int c_hash_stream(const char *file_name, FILE *fp, const struct stat *st,
                         os_md5 mf_sum, os_sha1 sf_sum, os_sha256 sha256_sum)
{
    strncpy(mf_sum, "xxx", 4);
    strncpy(sf_sum, "xxx", 4);
    strncpy(sha256_sum, "xxx", 4);

    if (syscheck.file_max_size > 0 && st != NULL && st->st_size > 0 &&
            (size_t)st->st_size > syscheck.file_max_size) {
        if (fp != NULL) {
            fclose(fp);
        }
        c_read_warn("%s: WARN: File '%s' is over the checksum size limit.",
                    ARGV0, file_name);
        return (1);
    }

    if (fp == NULL) {
        return (-1);
    }

    if (OS_MD5_SHA1_SHA256_Fp(fp, mf_sum, sf_sum, sha256_sum,
                              syscheck.file_max_size) < 0) {
        fclose(fp);
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
    fclose(fp);
    return (0);
}

int c_hash_file(const char *file_name, const struct stat *st,
                os_md5 mf_sum, os_sha1 sf_sum, os_sha256 sha256_sum)
{
    return (c_hash_stream(file_name, fim_fopen_monitored(file_name, 0),
                          st, mf_sum, sf_sum, sha256_sum));
}

int c_hash_file_follow(const char *file_name, const struct stat *st,
                       os_md5 mf_sum, os_sha1 sf_sum, os_sha256 sha256_sum)
{
    return (c_hash_stream(file_name, fim_fopen_monitored(file_name, 1),
                          st, mf_sum, sf_sum, sha256_sum));
}

int c_hash_entry(DIR *parent, const char *name, const char *file_name,
                 const struct stat *st,
                 os_md5 mf_sum, os_sha1 sf_sum, os_sha256 sha256_sum)
{
    int fd;
    struct stat opened;
    FILE *fp;

    if (syscheck.file_max_size > 0 && st != NULL && st->st_size > 0 &&
            (size_t)st->st_size > syscheck.file_max_size) {
        return (c_hash_stream(file_name, NULL, st, mf_sum, sf_sum, sha256_sum));
    }

    /* MinGW has no O_NONBLOCK or fcntl. A FIFO cannot block open() there. */
#ifndef WIN32
    fd = fim_open_entry(parent, name, file_name, O_RDONLY | O_NONBLOCK);
#else
    fd = fim_open_entry(parent, name, file_name, O_RDONLY);
#endif
    if (fd < 0 || fstat(fd, &opened) < 0 || !S_ISREG(opened.st_mode)) {
        if (fd >= 0) {
            close(fd);
        }
        return (c_hash_stream(file_name, NULL, st, mf_sum, sf_sum, sha256_sum));
    }
#ifndef WIN32
    {
        int flags = fcntl(fd, F_GETFL);

        if (flags != -1 && (flags & O_NONBLOCK)) {
            (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }
    }
#endif
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return (c_hash_stream(file_name, NULL, st, mf_sum, sf_sum, sha256_sum));
    }
    return (c_hash_stream(file_name, fp, st, mf_sum, sf_sum, sha256_sum));
}

/* Follow a symlink that is an entry of parent. The parent directory fd
 * stays pinned, so a swapped path is not walked again. */
int c_hash_entry_follow(DIR *parent, const char *name, const char *file_name,
                        const struct stat *st,
                        os_md5 mf_sum, os_sha1 sf_sum, os_sha256 sha256_sum)
{
    int fd;
    struct stat opened;
    FILE *fp;

    (void)st;
    strncpy(mf_sum, "xxx", 4);
    strncpy(sf_sum, "xxx", 4);
    strncpy(sha256_sum, "xxx", 4);

    if (parent == NULL || name == NULL) {
        return (c_hash_file_follow(file_name, st, mf_sum, sf_sum, sha256_sum));
    }

    fd = fim_open_entry_follow(parent, name, file_name);
    if (fd < 0 || fstat(fd, &opened) < 0 || !S_ISREG(opened.st_mode)) {
        if (fd >= 0) {
            close(fd);
        }
        return (0);
    }

#ifndef WIN32
    {
        int flags = fcntl(fd, F_GETFL);

        if (flags != -1 && (flags & O_NONBLOCK)) {
            (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }
    }
#endif
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return (-1);
    }
    return (c_hash_stream(file_name, fp, &opened, mf_sum, sf_sum, sha256_sum));
}
