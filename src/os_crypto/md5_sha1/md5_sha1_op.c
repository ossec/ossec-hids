/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef LIBSODIUM_ENABLED
#include <sodium.h>
#endif

#include "md5_sha1_op.h"
#include "../md5/md5.h"
#include "../sha1/sha.h"
#include "headers/defs.h"


int OS_MD5_SHA1_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output, int mode)
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

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
        fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
        if (!fp) {
            return (-1);
        }
    } else {
        char cmd[OS_MAXSTR];
        size_t target_length = strlen(prefilter_cmd) + 1 + strlen(fname);
        int res = snprintf(cmd, sizeof(cmd), "%s %s", prefilter_cmd, fname);
        if (res < 0 || (unsigned int)res != target_length) {
            return (-1);
        }
        fp = popen(cmd, "r");
        if (!fp) {
            return (-1);
        }
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

    /* Close it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return (0);
}


int OS_Hash_File(const char *fname, const char *prefilter_cmd, struct hash_output file_output, int mode, char **alg)
{
    size_t n;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char md5_digest[16];

    int c_sha1 = 0, c_md5 = 0, c_sha256 = 0, al = 0;
    while(alg[al]) {
        if((strncmp(alg[al], "md5", 3) == 0 || strncmp(alg[al],
                        "MD5", 3) == 0)) {
            c_md5 = 1;
        } else if((strncmp(alg[al], "sha1", 4) == 0 || strncmp(alg[al],
                        "SHA1", 4) == 0)) {
            c_sha1 = 1;
        } else if((strncmp(alg[al], "sha256", 6) == 0 || strncmp(alg[al],
                        "SHA256", 6) == 0)) {
#ifdef LIBSODIUM_ENABLED
            c_sha256 = 1;
#else
            //merror("syscheck: Not compiled with libsodium support, enabling sha1");
            c_sha1 = 1;
#endif
        }
        al++;
    }

#ifdef LIBSODIUM_ENABLED
    if(c_sha1 == 1 && c_sha256 == 1) {
        //merror("syscheckd: sha1 and sha256 enabled, disabling sha1.");
        c_sha1 = 0;
    }
#endif


    SHA_CTX sha1_ctx;
    MD5_CTX md5_ctx;

#ifdef LIBSODIUM_ENABLED
    // Initialize libsodium and clear the sha256output
    unsigned char sha256_digest[crypto_hash_sha256_BYTES];
    if(sodium_init() < 0) {
        //merror("Hash failed: (%d) %s", errno, strerror(errno));
        exit(errno);    // XXX - doesn't seem right
    }
    crypto_hash_sha256_state sha256_state;
    crypto_hash_sha256_init(&sha256_state);
    file_output.sha256output[0] = '\0';
#endif

    /* Clear the memory */
    file_output.md5output[0] = '\0';
    file_output.sha1output[0] = '\0';
    buf[2048 + 1] = '\0';

    /* Use prefilter_cmd if set */
    if (prefilter_cmd == NULL) {
        fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
        if (!fp) {
            return (-1);
        }
    } else {
        char cmd[OS_MAXSTR];
        size_t target_length = strlen(prefilter_cmd) + 1 + strlen(fname);
        int res = snprintf(cmd, sizeof(cmd), "%s %s", prefilter_cmd, fname);
        if (res < 0 || (unsigned int)res != target_length) {
            return (-1);
        }
        fp = popen(cmd, "r");
        if (!fp) {
            return (-1);
        }
    }

    /* Initialize both hashes */
    if(c_md5 > 0) {
        MD5Init(&md5_ctx);
    }
    if(c_sha1 > 0) {
        SHA1_Init(&sha1_ctx);
    }

    /* Update for each hash */
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        if(c_sha1 > 0) {
            SHA1_Update(&sha1_ctx, buf, n);
        }
        if(c_md5 > 0) {
            MD5Update(&md5_ctx, buf, (unsigned)n);
        }
#ifdef LIBSODIUM_ENABLED
        if(c_sha256 > 0) {
            crypto_hash_sha256_update(&sha256_state, buf, n);
        }
#endif
    }

    if(c_sha1 > 0) {
        SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    }
    if(c_md5 > 0) {
        MD5Final(md5_digest, &md5_ctx);
    }
#ifdef LIBSODIUM_ENABLED
    if(c_sha256 > 0) {
        crypto_hash_sha256_final(&sha256_state, sha256_digest);
    }
#endif

    /* Set output for MD5 */
    if(c_md5 > 0) {
        for (n = 0; n < 16; n++) {
            if(n == 0) {
                snprintf(file_output.md5output, 3, "%02x", md5_digest[n]);
            } else {
                snprintf(file_output.md5output, strnlen(file_output.md5output, 33) + 3, "%s%02x", file_output.md5output, md5_digest[n]);
            }
        }
    }

    /* Set output for SHA-1 */
    if(c_sha1 > 0) {
        for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
            if(n == 0) {
                snprintf(file_output.sha1output, 3, "%02x", sha1_digest[n]);
            } else {
                snprintf(file_output.sha1output, strnlen(file_output.sha1output, 65) + 3, "%s%02x", file_output.sha1output, sha1_digest[n]);
            }
        }
    }

#ifdef LIBSODIUM_ENABLED
    /* Set output for SHA256 */
    if(c_sha256 > 0) {
        for (n = 0; n < crypto_hash_sha256_BYTES; n++) {
            if(n == 0) {
                snprintf(file_output.sha256output, 3, "%02x", sha256_digest[n]);
            } else {
                snprintf(file_output.sha256output, strnlen(file_output.sha256output, 66) + 3, "%s%02x", file_output.sha256output, sha256_digest[n]);
            }
        }
    }
#endif

    /* Close it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return (0);
}

