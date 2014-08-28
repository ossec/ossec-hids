/*   $OSSEC, mail-config.h, v0.1, 2006/04/06, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef _MCCONFIG__H
#define _MCCONFIG__H
#include "shared.h"


/* Mail config structure */
typedef struct _MailConfig
{
    int mn;
    int maxperhour;
    int strict_checking;
    int groupping;
    int subject_full;
    int priority;
    char **to;
    char *from;
    char *idsname;
    char *smtpserver;

    /* Granular e-mail options */
    int *gran_level;
    int **gran_id;
    int *gran_set;
    int *gran_format;
    char **gran_to;

#ifdef GEOIP
    /* Use GeoIP */
    int geoip;
#endif

    OSMatch **gran_location;
    OSMatch **gran_group;
}MailConfig;


/** Email message formats **/
#define FULL_FORMAT     2
#define SMS_FORMAT      3
#define FORWARD_NOW     4
#define DONOTGROUP      5

#endif
