/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <errno.h>

#include "headers/shared.h"
#include "md5_sha1_op.h"
#include "../md5/md5.h"
#include "../sha1/sha.h"
#include "../sha256/sha256.h"


int OS_MD5_SHA1_File(const char *fname, os_md5 md5output, os_sha1 sha1output, int mode)
{
    size_t n;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];

    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;

    /* Clear the memory */
    md5output[0] = '\0';
    sha1output[0] = '\0';
    buf[2048 + 1] = '\0';

    /* User-controlled paths (FIM / rootcheck): refuse FIFO/device without
     * blocking (ANT-2026-KZAJSOET). */
#ifndef WIN32
    (void)mode;
    fp = fopen_regular(fname);
#else
    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
#endif
    if (!fp) {
        return (-1);
    }

    /* Initialize both hashes */
    MD5Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);

    /* Update for each one */
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        SHA1_Update(&sha1_ctx, buf, n);
        MD5Update(&md5_ctx, buf, (unsigned)n);
    }

    SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    MD5Final(md5_digest, &md5_ctx);

    /* Set output for MD5 */
    for (n = 0; n < 16; n++) {
        snprintf(md5output, 3, "%02x", md5_digest[n]);
        md5output += 2;
    }

    /* Set output for SHA-1 */
    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(sha1output, 3, "%02x", sha1_digest[n]);
        sha1output += 2;
    }

    fclose(fp);
    return (0);
}

int OS_MD5_SHA1_SHA256_File(const char *fname, os_md5 md5output, os_sha1 sha1output,
                            os_sha256 sha256output, int mode, size_t max_size)
{
    size_t n;
    size_t total = 0;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];
    unsigned char sha256_digest[32];
    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;
    SHA256_CTX sha256_ctx;

    md5output[0] = '\0';
    sha1output[0] = '\0';
    sha256output[0] = '\0';
    buf[2048 + 1] = '\0';

#ifndef WIN32
    (void)mode;
    fp = fopen_regular(fname);
#else
    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
#endif
    if (!fp) {
        return (-1);
    }

    MD5Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);
    os_SHA256_Init(&sha256_ctx);

    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        if (max_size > 0) {
            total += n;
            if (total > max_size) {
                fclose(fp);
                md5output[0] = '\0';
                sha1output[0] = '\0';
                sha256output[0] = '\0';
                errno = EFBIG;
                return (-1);
            }
        }
        buf[n] = '\0';
        SHA1_Update(&sha1_ctx, buf, n);
        MD5Update(&md5_ctx, buf, (unsigned)n);
        os_SHA256_Update(&sha256_ctx, buf, n);
    }

    SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    MD5Final(md5_digest, &md5_ctx);
    os_SHA256_Final(sha256_digest, &sha256_ctx);

    for (n = 0; n < 16; n++) {
        snprintf(md5output, 3, "%02x", md5_digest[n]);
        md5output += 2;
    }
    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        snprintf(sha1output, 3, "%02x", sha1_digest[n]);
        sha1output += 2;
    }
    for (n = 0; n < 32; n++) {
        snprintf(sha256output, 3, "%02x", sha256_digest[n]);
        sha256output += 2;
    }

    fclose(fp);
    return (0);
}
