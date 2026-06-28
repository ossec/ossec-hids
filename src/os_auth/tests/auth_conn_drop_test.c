/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * Standalone test for auth_conn_drop_pending() on queued pool tasks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "../../headers/shared.h"
#include "../auth_conn.h"

#ifndef ARGV0
#define ARGV0 "auth_conn_drop_test"
#endif

int main(void)
{
    auth_conn_arg *conn;
    int fds[2];

    assert(pipe(fds) == 0);

    conn = (auth_conn_arg *)calloc(1, sizeof(auth_conn_arg));
    assert(conn != NULL);
    conn->client_sock = fds[0];
    conn->srcip[0] = '\0';

    auth_conn_drop_pending(conn);

    assert(close(fds[1]) == 0);
    assert(close(fds[1]) == -1);

    printf("auth_conn_drop_test: OK\n");
    return 0;
}
