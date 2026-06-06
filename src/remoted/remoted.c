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

