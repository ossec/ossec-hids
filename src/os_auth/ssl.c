/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#ifdef LIBOPENSSL_ENABLED

#include "shared.h"
#include "auth.h"
#include <openssl/dh.h>

/* Global variables */
BIO *bio_err;


/* Create an SSL context. If certificate verification is requested
 * then load the file containing the CA chain and verify the certificate
 * sent by the peer.
 */
SSL_CTX *os_ssl_keys(int is_server, const char *os_dir, const char *ciphers, const char *cert, const char *key, const char *ca_cert)
{
    SSL_CTX *ctx = NULL;

    if (!(ctx = get_ssl_context(ciphers))) {
        goto SSL_ERROR;
    }

    /* If a CA certificate has been specified then load it and verify the peer */
    if (ca_cert) {
        debug1("%s: DEBUG: Peer verification requested.", ARGV0);

        if (!load_ca_cert(ctx, ca_cert)) {
            goto SSL_ERROR;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    }

    /* Loading a certificate and key is mandatory for the server and optional for clients */
    if (is_server) {
        char default_cert[PATH_MAX + 1];
        char default_key[PATH_MAX + 1];

        if (!cert) {
            snprintf(default_cert, PATH_MAX + 1, "%s%s", os_dir, CERTFILE);
            cert = default_cert;
        }

        if (!key) {
            snprintf(default_key, PATH_MAX + 1, "%s%s", os_dir, KEYFILE);
            key = default_key;
        }

        if (!load_cert_and_key(ctx, cert, key)) {
            goto SSL_ERROR;
        }

        debug1("%s: DEBUG: Returning CTX for server.", ARGV0);
    } else {
        if (cert && key) {
            if (!load_cert_and_key(ctx, cert, key)) {
                goto SSL_ERROR;
            }
        }

        debug1("%s: DEBUG: Returning CTX for client.", ARGV0);
    }

    return ctx;

SSL_ERROR:
    if (ctx) {
        SSL_CTX_free(ctx);
    }

    return (SSL_CTX *)NULL;
}

DH *get_dh2048()
{
    static const unsigned char dh2048_p[] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xAD,0xF8,0x54,0x58,0x72,0xDD,0x3B,0x75,
        0xDA,0x1A,0x41,0xE6,0x66,0xE5,0x3D,0xA8,0x3D,0xB0,0x9C,0x70,0xE8,0x60,0x95,0x69,
        0x8C,0x4C,0x13,0x35,0xCC,0x2B,0x0C,0x85,0x94,0xE6,0x9C,0x29,0x55,0x9E,0x74,0x0F,
        0x95,0x63,0xEB,0x1F,0x2A,0x0D,0x55,0xE3,0x8A,0xB7,0x1F,0x1D,0x36,0xD7,0x6D,0xC8,
        0x18,0x81,0xF7,0x35,0xF8,0x26,0x1C,0x79,0x05,0xAA,0x98,0xBD,0x17,0x71,0x10,0xD4,
        0xAF,0xCD,0x43,0xDC,0xE9,0x55,0xE2,0x84,0x7F,0xCA,0x8C,0x57,0x0D,0x5C,0x99,0xCA,
        0xC5,0xF6,0x3B,0x29,0x21,0x30,0x70,0x7C,0xA4,0xFF,0x5D,0x17,0x97,0x6D,0xE7,0x6F,
        0x13,0x11,0xE6,0x83,0xE6,0xBF,0x8A,0x0E,0x17,0x29,0x6A,0xD2,0xB9,0xA3,0xB9,0x05,
        0xE2,0x21,0xF2,0x48,0x5C,0xBB,0x21,0x4E,0xE6,0xBF,0xFB,0x85,0x0E,0xB3,0xCA,0x4B,
        0xE6,0xB0,0xEC,0xF2,0x6B,0x28,0xF5,0x65,0x02,0x43,0xB1,0xFB,0xA2,0x29,0x39,0xC5,
        0x41,0x56,0xB2,0x12,0x74,0x8E,0x62,0x19,0x54,0x5B,0x86,0x8F,0x0E,0xCC,0x67,0xC0,
        0x67,0x21,0xA0,0x24,0x6C,0xDB,0x59,0x11,0x77,0x6F,0xC5,0xAC,0xE6,0x83,0x20,0x49,
        0x89,0x37,0xA0,0x9B,0x8B,0x15,0x98,0x95,0xF6,0x0E,0x6F,0x67,0xEF,0x5C,0xB4,0xC4,
        0x41,0x62,0x59,0xD4,0x8D,0xED,0x84,0x68,0xEB,0x7D,0x5F,0x70,0xFA,0x67,0xEF,0x91,
        0x72,0x97,0x97,0xE9,0xF8,0x77,0x89,0x2F,0x0B,0x72,0x90,0x55,0x79,0xB4,0xB5,0x36,
        0x83,0xCD,0xD3,0xEE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    };
    static const unsigned char dh2048_g[] = { 0x02 };
    DH *dh;

    if ((dh = DH_new()) == NULL) return(NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    dh->g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);
    if (!dh->p || !dh->g) {
        DH_free(dh);
        return(NULL);
    }
#else
    BIGNUM *p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    BIGNUM *g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);
    if (!p || !g || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return(NULL);
    }
#endif
    return(dh);
}

SSL_CTX *get_ssl_context(const char *ciphers)
{
    const SSL_METHOD *sslmeth = NULL;
    SSL_CTX *ctx = NULL;
    DH *dh;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create our context */
    sslmeth = TLSv1_2_method();
    if (!(ctx = SSL_CTX_new(sslmeth))) {
        goto CONTEXT_ERR;
    }

    /* Explicitly set options and cipher list */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (!(SSL_CTX_set_cipher_list(ctx, ciphers))) {
        goto CONTEXT_ERR;
    }

    /* Initialize Diffie-Hellman parameters */
    if ((dh = get_dh2048())) {
        SSL_CTX_set_tmp_dh(ctx, dh);
        DH_free(dh);
    } else {
        merror("%s: ERROR: Unable to load DH parameters", ARGV0);
        goto CONTEXT_ERR;
    }

    return ctx;

CONTEXT_ERR:
    if (ctx) {
        SSL_CTX_free(ctx);
    }

    return (SSL_CTX *)NULL;
}

int load_cert_and_key(SSL_CTX *ctx, const char *cert, const char *key)
{
    if (File_DateofChange(cert) <= 0) {
        merror("%s: ERROR: Unable to read certificate file (not found): %s", ARGV0, cert);
        return 0;
    }

    if (!(SSL_CTX_use_certificate_chain_file(ctx, cert))) {
        merror("%s: ERROR: Unable to read certificate file: %s", ARGV0, cert);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (!(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM))) {
        merror("%s: ERROR: Unable to read private key file: %s", ARGV0, key);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        merror("%s: ERROR: Unable to verify private key file", ARGV0);
        ERR_print_errors_fp(stderr);
        return 0;
    }

#if(OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx, 1);
#endif

    return 1;
}

int load_ca_cert(SSL_CTX *ctx, const char *ca_cert)
{
    if (!ca_cert) {
        merror("%s: ERROR: Verification requested but no CA certificate file specified", ARGV0);
        return 0;
    }

    if (SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) != 1) {
        merror("%s: ERROR: Unable to read CA certificate file \"%s\"", ARGV0, ca_cert);
        return 0;
    }

    return 1;
}

/* No extra verification is done here. This function provides more
 * information in the case that certificate verification fails
 * for any reason.
 */
int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];

    if (!ok) {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);

        merror("%s: ERROR: Problem with certificate at depth %i", ARGV0, depth);

        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        merror("%s: ERROR: issuer =  %s", ARGV0, data);

        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        merror("%s: ERROR: subject =  %s", ARGV0, data);

        merror("%s: ERROR: %i:%s", ARGV0, err, X509_verify_cert_error_string(err));
    }

    return ok;
}

#endif /* LIBOPENSSL_ENABLED */

