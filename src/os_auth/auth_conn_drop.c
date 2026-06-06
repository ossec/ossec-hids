/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "auth_conn.h"
#include <unistd.h>
#include <stdlib.h>

void auth_conn_drop_pending(void *arg)
{
    auth_conn_arg *conn = (auth_conn_arg *)arg;

    if (!conn) {
        return;
    }

    if (conn->client_sock >= 0) {
        close(conn->client_sock);
    }
    free(conn);
}
