/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "agentd.h"

/* Global variables */
time_t available_server;
int run_foreground;
keystore keys;
agent *agt;
#ifndef WIN32
const char *cfgfile;
#endif


/* Free the agent configuration */
void FreeAgentConfig(agent *config)
{
    int i = 0;

    if (config->rip) {
        while (config->rip[i]) {
            free(config->rip[i]);
            i++;
        }
        free(config->rip);
        config->rip = NULL;
    }

    if (config->lip) {
        free(config->lip);
        config->lip = NULL;
    }

    if (config->profile) {
        free(config->profile);
        config->profile = NULL;
    }

    if (config->port) {
        free(config->port);
        config->port = NULL;
    }
}


/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile, agent *config)
{
    int modules = 0;
    os_strdup(DEFAULT_SECURE, config->port);
    config->rip = NULL;
    config->lip = NULL;
    config->rip_id = 0;
    config->execdq = 0;
    config->profile = NULL;

    modules |= CCLIENT;

    if (ReadConfig(modules, cfgfile, config, NULL) < 0) {
        return (OS_INVALID);
    }

    return (1);
}

