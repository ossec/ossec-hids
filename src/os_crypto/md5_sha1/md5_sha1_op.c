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

#ifdef LIBSODIUM_ENABLED
int OS_Hash_File(const char *fname, const char *prefilter_cmd, struct hash_output *file_output, int mode)
{

    size_t n;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md5_digest[16];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    unsigned char generic_digest[crypto_generichash_BYTES_MAX];
    unsigned char sha256_digest[crypto_hash_sha256_BYTES];

    /* Declare and init the hashes */
    MD5_CTX md5_ctx;
    if(file_output->check_md5) {
        MD5Init(&md5_ctx);
    }

    SHA_CTX sha1_ctx;
    if(file_output->check_sha1) {
        SHA1_Init(&sha1_ctx);
    }

    crypto_hash_sha256_state sha256_state;
    crypto_generichash_state generic_state;

    /* Initialize libsodium */
    if((file_output->check_sha256 > 0) || (file_output->check_generic) > 0) {
        if(sodium_init() < 0) {
            exit(errno);    // XXX - doesn't seem right
        }
    }
    if(file_output->check_sha256) {
        crypto_hash_sha256_init(&sha256_state);
    }

    if(file_output->check_generic) {
        crypto_generichash_init(&generic_state, NULL, 0, sizeof(generic_digest));
    }

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

    /* Update for each hash */
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        if(file_output->check_md5) {
            MD5Update(&md5_ctx, buf, (unsigned)n);
        }
        if(file_output->check_sha256) {
            crypto_hash_sha256_update(&sha256_state, buf, n);
        }
        if(file_output->check_sha1) {
            SHA1_Update(&sha1_ctx, buf, n);
        }
        if(file_output->check_generic) {
            crypto_generichash_update(&generic_state, buf, n);
        }
    }

    if(file_output->check_md5) {
        MD5Final(md5_digest, &md5_ctx);
    }
    if(file_output->check_sha256) {
        crypto_hash_sha256_final(&sha256_state, sha256_digest);
    }
    if(file_output->check_sha1) {
        SHA1_Final(&(sha1_digest[0]), &sha1_ctx);
    }
    if(file_output->check_generic) {
        crypto_generichash_final(&generic_state, generic_digest, crypto_generichash_BYTES_MAX);
    }

    /* Set output for MD5 */
    char hashtmp[3];

    if(file_output->check_md5) {
        for (n = 0; n < 16; n++) {
            hashtmp[0] = '\0';
            snprintf(hashtmp, 3, "%02x", md5_digest[n]);
            strncat(file_output->md5output, hashtmp, 2);
        }
    }
    if(file_output->check_sha1) {
        for (n = 0; n < 16; n++) {
            hashtmp[0] = '\0';
            snprintf(hashtmp, 3, "%02x", sha1_digest[n]);
            strncat(file_output->sha1output, hashtmp, 2);
        }
    }
    if(file_output->check_generic) {
        for (n = 0; n < crypto_generichash_BYTES_MAX; ++n) {
            hashtmp[0] = '\0';
            snprintf(hashtmp, 3, "%02x", generic_digest[n]);
            strncat(file_output->genericoutput, hashtmp,2);
        }
    }
    if(file_output->check_sha256) {
        for (n = 0; n < crypto_hash_sha256_BYTES; ++n) {
            hashtmp[0] = '\0';
            snprintf(hashtmp, 3, "%02x", sha256_digest[n]);
            strncat(file_output->sha256output, hashtmp, 2);
        }
    }





    /* Close it */
    if (prefilter_cmd == NULL) {
        fclose(fp);
    } else {
        pclose(fp);
    }

    return (0);
}
#endif  // LIBSODIUM_ENABLED

