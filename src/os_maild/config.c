/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "maild.h"
#include "config/config.h"

static void MailConf_clear_smtp_config(MailConfig *Mail)
{
    if (Mail->smtp_user) {
        memset_secure(Mail->smtp_user, 0, strlen(Mail->smtp_user));
        free(Mail->smtp_user);
        Mail->smtp_user = NULL;
    }

    if (Mail->smtp_pass) {
        memset_secure(Mail->smtp_pass, 0, strlen(Mail->smtp_pass));
        free(Mail->smtp_pass);
        Mail->smtp_pass = NULL;
    }

#ifdef USE_SMTP_CURL
    if (Mail->smtpserver_resolved) {
        free(Mail->smtpserver_resolved);
        Mail->smtpserver_resolved = NULL;
    }
#endif
}

/* Free the Mail configuration */
void FreeMailConfig(MailConfig *Mail)
{

    if (Mail->to) {
        char **tmp = Mail->to;
        while (*tmp) {
            free(*tmp);
            tmp++;
        }
        free(Mail->to);
        Mail->to = NULL;
    }

    free(Mail->reply_to);
    free(Mail->from);
    free(Mail->idsname);
    free(Mail->smtpserver);
    free(Mail->heloserver);

    Mail->reply_to = NULL;
    Mail->from = NULL;
    Mail->idsname = NULL;
    Mail->smtpserver = NULL;
    Mail->heloserver = NULL;

    MailConf_clear_smtp_config(Mail);

    if (Mail->gran_to) {
        char **tmp = Mail->gran_to;
        while (*tmp) {
            free(*tmp);
            tmp++;
        }
        free(Mail->gran_to);
        Mail->gran_to = NULL;
    }

    if (Mail->gran_id) {
        unsigned int **tmp = Mail->gran_id;
        while (*tmp) {
            free(*tmp);
            tmp++;
        }
        free(Mail->gran_id);
        Mail->gran_id = NULL;
    }

    if (Mail->gran_location) {
        OSMatch **tmp = Mail->gran_location;
        while (*tmp) {
            OSMatch_FreePattern(*tmp);
            free(*tmp);
            tmp++;
        }
        free(Mail->gran_location);
        Mail->gran_location = NULL;
    }

    if (Mail->gran_group) {
        OSMatch **tmp = Mail->gran_group;
        while (*tmp) {
            OSMatch_FreePattern(*tmp);
            free(*tmp);
            tmp++;
        }
        free(Mail->gran_group);
        Mail->gran_group = NULL;
    }

    free(Mail->gran_level);
    free(Mail->gran_set);
    free(Mail->gran_format);

    Mail->gran_level = NULL;
    Mail->gran_set = NULL;
    Mail->gran_format = NULL;
}


/* Read the Mail configuration */
int MailConf(int test_config, const char *cfgfile, MailConfig *Mail)
{
    int modules = 0;

    modules |= CMAIL;

    Mail->to = NULL;
    Mail->reply_to = NULL;
    Mail->from = NULL;
    Mail->idsname = NULL;
    Mail->smtpserver = NULL;
    Mail->heloserver = NULL;
    Mail->smtpserver_resolved = NULL;
    Mail->authsmtp = 0;
    Mail->securesmtp = 0;
    Mail->smtp_port = 0;
    Mail->smtp_user = NULL;
    Mail->smtp_pass = NULL;
    Mail->mn = 0;
    Mail->priority = 0;
    Mail->maxperhour = 12;
    Mail->gran_to = NULL;
    Mail->gran_id = NULL;
    Mail->gran_level = NULL;
    Mail->gran_location = NULL;
    Mail->gran_group = NULL;
    Mail->gran_set = NULL;
    Mail->gran_format = NULL;
    Mail->groupping = 1;
    Mail->strict_checking = 0;
#ifdef LIBGEOIP_ENABLED
    Mail->geoip = 0;
#endif

    if (ReadConfig(modules, cfgfile, NULL, Mail) < 0) {
        MailConf_clear_smtp_config(Mail);
        return (OS_INVALID);
    }

#ifndef USE_SMTP_CURL
    if (Mail->authsmtp || Mail->securesmtp || Mail->smtp_port ||
        Mail->smtp_user || Mail->smtp_pass) {
        merror("%s: SMTP authentication/TLS options (auth_smtp, secure_smtp, smtp_port, smtp_user, smtp_password) require building with USE_CURL=yes.", ARGV0);
        MailConf_clear_smtp_config(Mail);
        return (OS_INVALID);
    }
#else
    if (Mail->authsmtp && (!Mail->smtp_user || !Mail->smtp_pass)) {
        merror("%s: auth_smtp=yes requires both smtp_user and smtp_password to be set.", ARGV0);
        MailConf_clear_smtp_config(Mail);
        return (OS_INVALID);
    }
#endif

    if (!Mail->mn) {
        if (!test_config) {
            verbose(MAIL_DIS, ARGV0);
            return (1);
        }
        MailConf_clear_smtp_config(Mail);
        exit(0);
    }

    return (0);
}
