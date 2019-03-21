/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __CAGENTD_H
#define __CAGENTD_H

#ifndef WIN32
#include <imsg.h>
#endif //WIN32

/* Configuration structure */
typedef struct _agent {
    char *port;
    int m_queue;
    int sock;
    int execdq;
    int rip_id;
    char *lip;
    char **rip; /* remote (server) IP */
    int notify_time;
    int max_time_reconnect_try;
    char *profile;

#ifdef WIN32
    struct imsgbuf ibuf;
#endif //WIN32

} agent;

#endif /* __CAGENTD_H */

