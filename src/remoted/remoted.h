/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __LOGREMOTE_H
#define __LOGREMOTE_H

#ifndef ARGV0
#define ARGV0 "ossec-remoted"
#endif

#include "config/remote-config.h"
#include "sec.h"
#include "thread_pool.h"

/** Per-listener runtime state (one thread per listener) */
typedef struct remoted_listener {
    int sock;
    OSNetInfo *netinfo;
    int m_queue;
    socklen_t peer_size;
    pthread_mutex_t mq_mutex;
    thread_pool *syslog_tcp_pool;
} remoted_listener;

/** Function prototypes **/

/* Read remoted config */
int RemotedConfig(const char *cfgfile, remoted *cfg);

/* Bind listener sockets before privilege drop (main thread only) */
int remoted_bind_listener(int position);

/* Handle Remote connections (sockets must already be bound) */
void HandleRemote(int position);

/* Handle Syslog */
void HandleSyslog(void);

/* Handle Syslog TCP */
void HandleSyslogTCP(void);

/* Handle Secure connections */
void HandleSecure(void);

/* Forward active response events */
void *AR_Forward(void *arg) __attribute__((noreturn));

/* Initialize the manager */
void manager_init(int isUpdate);

/* Wait for messages from the agent to analyze */
void *wait_for_msgs(void *none);

/* Save control messages */
void save_controlmsg(unsigned int agentid, char *msg);

/* Send message to agent on the given secure/syslog listener */
int send_msg(remoted_listener *listener, unsigned int agentid, const char *msg);

/* Initializing send_msg */
void send_msg_init(void);

void sendmsg_lock(void);
void sendmsg_unlock(void);

int check_keyupdate(void);

void key_lock(void);

void key_unlock(void);

void keyupdate_init(void);

/* Thread-safe send on the listener message queue (loc = SYSLOG_MQ or SECURE_MQ) */
int remoted_send_mq_msg(remoted_listener *listener, const char *msg,
                        const char *srcip, char loc);

int remoted_send_syslog_msg(remoted_listener *listener, const char *msg,
                            const char *srcip);

/** Global variables **/

extern keystore keys;
extern remoted logr;
extern remoted_listener remoted_listeners[REMOTE_LISTENERS_MAX];
extern __thread remoted_listener *remoted_self;
/* Set in HandleSecure(); used by AR_Forward and wait_for_msgs */
extern remoted_listener *remoted_secure_listener;

extern volatile sig_atomic_t remoted_shutting_down;

#define REMOTED_SHUTDOWN_POOL_TIMEOUT 60

void remoted_request_shutdown(int sig);
void remoted_close_listeners(void);
int remoted_wait_for_shutdown(void);
void remoted_destroy_tcp_pools(void);

#endif /* __LOGREMOTE_H */
