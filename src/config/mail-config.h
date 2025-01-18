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

#ifndef WIN32
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <imsg.h>
#endif //WIN32

#include "shared.h"

/* Mail config structure */
typedef struct _MailConfig {
    int mn;
    int maxperhour;
    int strict_checking;
    int groupping;
    int subject_full;
    int priority;
    char **to;
    char *reply_to;
    char *from;
    char *idsname;
    char *smtpserver;
    char *heloserver;

    /* auth smtp options */
    int authsmtp;
    char *smtp_user;
    char *smtp_pass;
    int securesmtp;

    /* Granular e-mail options */
    unsigned int *gran_level;
    unsigned int **gran_id;
    int *gran_set;
    int *gran_format;
    char **gran_to;

#ifdef LIBGEOIP_ENABLED
    /* Use GeoIP */
    int geoip;
#endif

#ifndef WIN32
    /* ibuf for imsg */
    struct imsgbuf ibuf;
#endif //WIN32

    OSMatch **gran_location;
    OSMatch **gran_group;
} MailConfig;

/* Email message formats */
#define FULL_FORMAT     2
#define SMS_FORMAT      3
#define FORWARD_NOW     4
#define DONOTGROUP      5

#endif /* _MCCONFIG__H */

