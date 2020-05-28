/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _REPORTSCONFIG_H
#define _REPORTSCONFIG_H

//#include "report_op.h"

typedef struct _monitor_config {
    unsigned short int day_wait;
    short int compress;
    short int sign;
    short int monitor_agents;
    int a_queue;
    int notify_time;

    char *smtpserver;
    char *emailfrom;
    char *emailidsname;

    char **agents;
} monitor_config;

#endif /* _REPORTSCONFIG_H */
