/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* remote daemon
 * Listen to remote packets and forward them to the analysis system
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

/* Global variables */
keystore keys;
remoted logr;
remoted_listener remoted_listeners[REMOTE_LISTENERS_MAX];
__thread remoted_listener *remoted_self = NULL;
remoted_listener *remoted_secure_listener = NULL;
volatile sig_atomic_t remoted_shutting_down = 0;

void remoted_request_shutdown(int sig)
{
    if (!remoted_shutting_down) {
        remoted_shutting_down = 1;
        merror("%s: Shutdown requested (signal %d); closing listeners.",
               ARGV0, sig);
        remoted_close_listeners();
        return;
    }

    merror(SIGNAL_RECV, ARGV0, sig, strsignal(sig));
    DeletePID(ARGV0);
    exit(1);
}

void remoted_close_listeners(void)
{
    int i;
    int j;

    for (i = 0; i < REMOTE_LISTENERS_MAX; i++) {
        remoted_listener *listener = &remoted_listeners[i];

        if (listener->netinfo == NULL) {
            continue;
        }

        for (j = 0; j < listener->netinfo->fdcnt; j++) {
            if (listener->netinfo->fds[j] >= 0) {
                close(listener->netinfo->fds[j]);
            }
        }
    }
}

static int remoted_pools_active(void)
{
    int i;
    int total = 0;

    for (i = 0; i < REMOTE_LISTENERS_MAX; i++) {
        if (remoted_listeners[i].syslog_tcp_pool) {
            total += thread_pool_active(remoted_listeners[i].syslog_tcp_pool);
        }
    }

    return total;
}

int remoted_wait_for_shutdown(void)
{
    /* Syslog TCP pools only; see src/remoted/README (Shutdown). */
    time_t start = 0;
    time_t now;

    while (1) {
        if (remoted_pools_active() == 0) {
            verbose("%s: Shutdown complete (no active syslog TCP workers).", ARGV0);
            remoted_destroy_tcp_pools();
            DeletePID(ARGV0);
            return 0;
        }

        now = time(NULL);
        if (start == 0) {
            start = now;
        }

        if ((now - start) >= REMOTED_SHUTDOWN_POOL_TIMEOUT) {
            merror("%s: Shutdown timeout (%d s) with syslog TCP work still active.",
                   ARGV0, REMOTED_SHUTDOWN_POOL_TIMEOUT);
            remoted_destroy_tcp_pools();
            DeletePID(ARGV0);
            return 1;
        }

        sleep(1);
    }
}

void remoted_destroy_tcp_pools(void)
{
    int i;

    for (i = 0; i < REMOTE_LISTENERS_MAX; i++) {
        if (remoted_listeners[i].syslog_tcp_pool) {
            thread_pool_destroy(remoted_listeners[i].syslog_tcp_pool);
            remoted_listeners[i].syslog_tcp_pool = NULL;
        }
    }
}


/* Bind one listener (called from main before setuid and before listener threads) */
int remoted_bind_listener(int position)
{
    remoted_listener *listener;

    if (position < 0 || position >= REMOTE_LISTENERS_MAX) {
        ErrorExit("%s: Invalid listener position %d", ARGV0, position);
    }

    listener = &remoted_listeners[position];
    listener->sock = 0;
    listener->netinfo = NULL;
    listener->m_queue = -1;
    listener->peer_size = 0;
    listener->syslog_tcp_pool = NULL;
    os_mutex_init(&listener->mq_mutex, NULL);

    /* If syslog connection and allowips is not defined, exit */
    if (logr.conn[position] == SYSLOG_CONN) {
        if (logr.allowips == NULL) {
            ErrorExit(NO_SYSLOG, ARGV0);
        } else {
            os_ip **tmp_ips;

            tmp_ips = logr.allowips;
            while (*tmp_ips) {
                verbose("%s: Remote syslog allowed from: '%s'",
                        ARGV0, (*tmp_ips)->ip);
                tmp_ips++;
            }
        }
    }

    /* Bind TCP */
    if (logr.proto[position] == IPPROTO_TCP) {
        listener->netinfo = OS_Bindporttcp(logr.port[position], logr.lip[position]);
        if (listener->netinfo->status < 0) {
            ErrorExit(BIND_ERROR, ARGV0, logr.port[position]);
        }
    } else {
        listener->netinfo = OS_Bindportudp(logr.port[position], logr.lip[position]);
        if (listener->netinfo->status < 0) {
            ErrorExit(BIND_ERROR, ARGV0, logr.port[position]);
        }
    }

    return (0);
}

/* Handle remote connections */
void HandleRemote(int position)
{
    if (position < 0 || position >= REMOTE_LISTENERS_MAX) {
        ErrorExit("%s: Invalid listener position %d", ARGV0, position);
    }

    remoted_self = &remoted_listeners[position];
    if (remoted_self->netinfo == NULL) {
        ErrorExit("%s: Listener %d is not bound.", ARGV0, position);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* If secure connection, deal with it */
    if (logr.conn[position] == SECURE_CONN) {
        HandleSecure();
    }

    else if (logr.proto[position] == IPPROTO_TCP)
    {
        HandleSyslogTCP();
    }

    /* If not, deal with syslog */
    else {
        HandleSyslog();
    }
}

int remoted_send_mq_msg(remoted_listener *listener, const char *msg,
                        const char *srcip, char loc)
{
    if (!listener || !msg || !srcip) {
        return -1;
    }

    os_mutex_lock(&listener->mq_mutex);

    if (SendMSG(listener->m_queue, msg, srcip, loc) < 0) {
        merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

        listener->m_queue = StartMQ(DEFAULTQUEUE, WRITE);
        if (listener->m_queue < 0) {
            os_mutex_unlock(&listener->mq_mutex);
            return -1;
        }

        if (SendMSG(listener->m_queue, msg, srcip, loc) < 0) {
            os_mutex_unlock(&listener->mq_mutex);
            return -1;
        }
    }

    os_mutex_unlock(&listener->mq_mutex);
    return 0;
}

int remoted_send_syslog_msg(remoted_listener *listener, const char *msg,
                            const char *srcip)
{
    return remoted_send_mq_msg(listener, msg, srcip, SYSLOG_MQ);
}

