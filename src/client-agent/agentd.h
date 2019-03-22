/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __AGENTD_H
#define __AGENTD_H

#include "config/config.h"
#include "config/client-config.h"

#ifndef WIN32
#include <imsg.h>
#endif //WIN32

/*** Function Prototypes ***/

/* Client configuration */
int ClientConf(const char *cfgfile);

/* Agentd init function */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group) __attribute__((noreturn));

/* Event Forwarder */
#ifdef WIN32
void *EventForward(void);
#else
void *EventForward(void);
#endif //WIN32

/* Receiver messages */
void *receive_msg(void);

/* Receiver messages for Windows */
void *receiver_thread(void *none);

/* Send integrity checking information about a file to the server */
int intcheck_file(const char *file_name, const char *dir);

/* Send message to server */
int send_msg(int agentid, const char *msg);

/* Extract the shared files */
char *getsharedfiles(void);

/* Initialize handshake to server */
#ifdef WIN32
void start_agent(int is_startup);
#else
void start_agent(int is_startup);
#endif

/* Connect to the server */
#ifdef WIN32
int connect_server(int initial_id);
#else
int connect_server(int initial_id);
#endif

/* Notify server */
#ifdef WIN32
void run_notify(void);
#else
void run_notify(void);
#endif

/* libevent callback */
void os_agent_cb(int fd, short ev, void *arg);

/*** Global variables ***/

/* Global variables. Only modified during startup. */

#include "shared.h"
#include "sec.h"

extern time_t available_server;
extern int run_foreground;
extern keystore keys;
extern agent *agt;
#ifndef WIN32
struct imsgbuf server_ibuf;
#endif //WIN32

#endif /* __AGENTD_H */

