/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CSYSLOG_TLS_H
#define CSYSLOG_TLS_H

#include "config/csyslogd-config.h"

#ifdef LIBOPENSSL_ENABLED

#include <openssl/ssl.h>

/* Create a client SSL_CTX. verify=1 enables peer verification.
 * ca_path may be NULL to use the default system trust store.
 */
SSL_CTX *csyslog_tls_ctx_create(int verify, const char *ca_path);

/* Perform TLS handshake on an already-connected TCP fd.
 * hostname is used for SNI and (when verify) hostname checks.
 */
SSL *csyslog_tls_connect(SSL_CTX *ctx, int fd, const char *hostname, int verify);

/* Write len bytes; handles partial SSL_write. Returns 0 on success, -1 on error. */
int csyslog_tls_write(SSL *ssl, const char *buf, size_t len);

void csyslog_tls_close(SSL **ssl);
void csyslog_tls_ctx_free(SSL_CTX **ctx);

#endif /* LIBOPENSSL_ENABLED */

#endif /* CSYSLOG_TLS_H */
