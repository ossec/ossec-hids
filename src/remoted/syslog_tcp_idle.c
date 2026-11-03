/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "remoted.h"

#include <errno.h>

/* After syslog_recv_buffer returned r_sz (<= 0) with errno err, decide
 * whether syslog_client_worker should close the client. Quiet SO_RCVTIMEO
 * (EAGAIN/EWOULDBLOCK) keeps a live forwarder while the pool has room;
 * EOF, unanswered keepalive (ETIMEDOUT), and other errors always close.
 * pool_should_drop comes from thread_pool_should_drop_idle() so a timeout
 * herd cannot drop more quiet clients than there are queued waiters.
 * ANT-2026-QY1SHLVV.
 */
int syslog_tcp_should_close_on_recv(int r_sz, int err, int pool_should_drop)
{
    if (r_sz == 0) {
        return (1);
    }

    if (r_sz < 0 && (err == EAGAIN || err == EWOULDBLOCK)) {
        return (pool_should_drop ? 1 : 0);
    }

    return (1);
}
