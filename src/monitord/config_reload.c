/* Copyright (C) 2026 Atomicorp Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ARGV0
#define ARGV0 "ossec-monitord"
#endif

#include "shared.h"
#include "config/config.h"
#include "monitord.h"

const char *mond_cfgfile = NULL;

void FreeMonitordConfig(monitor_config *config)
{
    int i = 0;
    int j = 0;

    if (!config) {
        return;
    }

    if (config->reports) {
        while (config->reports[i]) {
            free(config->reports[i]->title);
            free(config->reports[i]->args);
            free(config->reports[i]->relations);
            free(config->reports[i]->type);
            if (config->reports[i]->emailto) {
                j = 0;
                while (config->reports[i]->emailto[j]) {
                    free(config->reports[i]->emailto[j]);
                    j++;
                }
                free(config->reports[i]->emailto);
            }
            free(config->reports[i]->r_filter.group);
            free(config->reports[i]->r_filter.rule);
            free(config->reports[i]->r_filter.level);
            free(config->reports[i]->r_filter.location);
            free(config->reports[i]->r_filter.srcip);
            free(config->reports[i]->r_filter.user);
            free(config->reports[i]->r_filter.report_name);
            free(config->reports[i]);
            i++;
        }
        free(config->reports);
        config->reports = NULL;
    }

    if (config->agents) {
        i = 0;
        while (config->agents[i]) {
            free(config->agents[i]);
            i++;
        }
        free(config->agents);
        config->agents = NULL;
    }

    free(config->smtpserver);
    free(config->smtpserver_resolved);
    free(config->emailfrom);
    free(config->emailidsname);
    free(config->smtp_user);
    free(config->smtp_pass);

    config->smtpserver = NULL;
    config->smtpserver_resolved = NULL;
    config->emailfrom = NULL;
    config->emailidsname = NULL;
    config->smtp_user = NULL;
    config->smtp_pass = NULL;
}

int MonitordReloadConfig(void)
{
    monitor_config new_mond;
    int modules = CREPORTS;

    if (!mond_cfgfile) {
        return (OS_INVALID);
    }

    memset(&new_mond, 0, sizeof(monitor_config));
    new_mond.day_wait = mond.day_wait;
    new_mond.compress = mond.compress;
    new_mond.sign = mond.sign;
    new_mond.monitor_agents = mond.monitor_agents;
    new_mond.notify_time = mond.notify_time;
    new_mond.a_queue = mond.a_queue;

    if (ReadConfig(modules, mond_cfgfile, &new_mond, NULL) < 0) {
        FreeMonitordConfig(&new_mond);
        return (OS_INVALID);
    }

    /* Email/SMTP settings cannot be re-resolved after chroot; keep current */
    new_mond.smtpserver = mond.smtpserver;
    new_mond.smtpserver_resolved = mond.smtpserver_resolved;
    new_mond.emailfrom = mond.emailfrom;
    new_mond.emailidsname = mond.emailidsname;
    new_mond.authsmtp = mond.authsmtp;
    new_mond.securesmtp = mond.securesmtp;
    new_mond.smtp_tls_verify = mond.smtp_tls_verify;
    new_mond.smtp_port = mond.smtp_port;
    new_mond.smtp_user = mond.smtp_user;
    new_mond.smtp_pass = mond.smtp_pass;

    mond.smtpserver = NULL;
    mond.smtpserver_resolved = NULL;
    mond.emailfrom = NULL;
    mond.emailidsname = NULL;
    mond.smtp_user = NULL;
    mond.smtp_pass = NULL;

    FreeMonitordConfig(&mond);
    memcpy(&mond, &new_mond, sizeof(monitor_config));

    return (0);
}
