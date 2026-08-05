/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Optional TLS for syslog_output (LIBOPENSSL_ENABLED).
 */

#include "shared.h"
#include "csyslog_tls.h"

#ifdef LIBOPENSSL_ENABLED

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <poll.h>

#ifndef CSYSLOG_TLS_WRITE_MAX_SPIN
#define CSYSLOG_TLS_WRITE_MAX_SPIN 10000
#endif

#ifndef CSYSLOG_TLS_WRITE_WAIT_MS
#define CSYSLOG_TLS_WRITE_WAIT_MS 1000
#endif

static void csyslog_tls_log_errors(const char *prefix)
{
    unsigned long e;

    while ((e = ERR_get_error()) != 0) {
        char buf[256];

        ERR_error_string_n(e, buf, sizeof(buf));
        merror("%s: ERROR: %s: %s", ARGV0, prefix, buf);
    }
}

SSL_CTX *csyslog_tls_ctx_create(int verify, const char *ca_path)
{
    SSL_CTX *ctx;
    const SSL_METHOD *method;
    static int ssl_inited = 0;

    if (!ssl_inited) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#endif
        ssl_inited = 1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    method = TLS_client_method();
#else
    method = TLSv1_2_client_method();
#endif

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        merror("%s: ERROR: SSL_CTX_new failed for syslog TLS.", ARGV0);
        csyslog_tls_log_errors("SSL_CTX_new");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#else
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                        SSL_OP_NO_TLSv1_1);
#endif

    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (ca_path && ca_path[0] != '\0') {
            if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
                merror("%s: ERROR: Unable to load TLS CA file '%s' for syslog_output.",
                       ARGV0, ca_path);
                csyslog_tls_log_errors("load CA");
                SSL_CTX_free(ctx);
                return NULL;
            }
        } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            merror("%s: ERROR: Unable to load default TLS CA paths for syslog_output.",
                   ARGV0);
            csyslog_tls_log_errors("default CA paths");
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        verbose("%s: INFO: syslog_output TLS certificate verification disabled "
                "(tls_verify=no).", ARGV0);
    }

    return ctx;
}

SSL *csyslog_tls_connect(SSL_CTX *ctx, int fd, const char *hostname, int verify)
{
    SSL *ssl;
    int ret;
    int is_ip;

    if (!ctx || fd < 0) {
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        merror("%s: ERROR: SSL_new failed for syslog TLS.", ARGV0);
        csyslog_tls_log_errors("SSL_new");
        return NULL;
    }

    if (SSL_set_fd(ssl, fd) != 1) {
        merror("%s: ERROR: SSL_set_fd failed for syslog TLS.", ARGV0);
        SSL_free(ssl);
        return NULL;
    }

    /* OS_IsValidIP == 1 means bare host address (not CIDR). Skip SNI for IPs. */
    is_ip = (hostname && hostname[0] != '\0' &&
             OS_IsValidIP(hostname, NULL) == 1) ? 1 : 0;

    if (hostname && hostname[0] != '\0' && !is_ip) {
#if OPENSSL_VERSION_NUMBER >= 0x0090806fL
        if (SSL_set_tlsext_host_name(ssl, hostname) != 1) {
            merror("%s: ERROR: Unable to set TLS SNI for '%s'.", ARGV0, hostname);
            SSL_free(ssl);
            return NULL;
        }
#endif
    }

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (verify && hostname && hostname[0] != '\0') {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        if (param) {
            X509_VERIFY_PARAM_set_hostflags(param, 0);
            if (is_ip) {
                if (X509_VERIFY_PARAM_set1_ip_asc(param, hostname) != 1) {
                    merror("%s: ERROR: Unable to set TLS IP check for '%s'.",
                           ARGV0, hostname);
                    SSL_free(ssl);
                    return NULL;
                }
            } else if (X509_VERIFY_PARAM_set1_host(param, hostname, 0) != 1) {
                merror("%s: ERROR: Unable to set TLS hostname check for '%s'.",
                       ARGV0, hostname);
                SSL_free(ssl);
                return NULL;
            }
        }
    }
#else
    /* Hostname/IP identity checks need OpenSSL 1.0.2+. Fail closed when
     * tls_verify=yes rather than accepting any peer name. */
    if (verify) {
        merror("%s: ERROR: syslog_output tls_verify=yes requires OpenSSL 1.0.2+ "
               "for hostname/IP certificate checks.", ARGV0);
        SSL_free(ssl);
        return NULL;
    }
    (void)is_ip;
#endif

    ret = SSL_connect(ssl);
    if (ret != 1) {
        merror("%s: ERROR: SSL_connect failed for syslog TLS to '%s' (ret=%d).",
               ARGV0, hostname ? hostname : "?", ret);
        csyslog_tls_log_errors("SSL_connect");
        SSL_free(ssl);
        return NULL;
    }

    if (verify) {
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK) {
            merror("%s: ERROR: syslog TLS peer verification failed: %s",
                   ARGV0, X509_verify_cert_error_string(vr));
            SSL_free(ssl);
            return NULL;
        }
    }

    return ssl;
}

int csyslog_tls_write(SSL *ssl, const char *buf, size_t len)
{
    size_t off = 0;
    int spins = 0;
    int fd;

    if (!ssl || !buf) {
        return -1;
    }

    fd = SSL_get_fd(ssl);

    while (off < len) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (++spins > CSYSLOG_TLS_WRITE_MAX_SPIN) {
                    return -1;
                }
                if (fd >= 0) {
                    struct pollfd pfd;

                    pfd.fd = fd;
                    pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
                    pfd.revents = 0;
                    if (poll(&pfd, 1, CSYSLOG_TLS_WRITE_WAIT_MS) <= 0) {
                        return -1;
                    }
                }
                continue;
            }
            return -1;
        }
        spins = 0;
        off += (size_t)n;
    }

    return 0;
}

void csyslog_tls_close(SSL **ssl)
{
    if (!ssl || !*ssl) {
        return;
    }
    /* Avoid blocking bidirectional shutdown on a dead peer. */
    SSL_set_quiet_shutdown(*ssl, 1);
    SSL_shutdown(*ssl);
    SSL_free(*ssl);
    *ssl = NULL;
}

void csyslog_tls_ctx_free(SSL_CTX **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    SSL_CTX_free(*ctx);
    *ctx = NULL;
}

#endif /* LIBOPENSSL_ENABLED */
