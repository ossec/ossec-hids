/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AUTH_CONN_H
#define AUTH_CONN_H

#include <openssl/ssl.h>

void auth_keys_init(void);
void auth_keys_lock(void);
void auth_keys_unlock(void);

typedef struct auth_conn_arg {
    int client_sock;
    char srcip[IPSIZE + 1];
    int use_ip_address;
    char *authpass;
    SSL_CTX *ctx;
} auth_conn_arg;

void *auth_connection_worker(void *arg);

void auth_conn_drop_pending(void *arg);

#endif /* AUTH_CONN_H */
