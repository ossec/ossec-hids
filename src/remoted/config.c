/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
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
#include "remoted.h"
#include "config/config.h"


/* Read the config file (the remote access) */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int modules = 0;

    modules |= CREMOTE;

    cfg->port = NULL;
    cfg->conn = NULL;
    cfg->proto = NULL;
    cfg->ipv6 = NULL;
    cfg->lip = NULL;
    cfg->allowips = NULL;
    cfg->denyips = NULL;

    if (ReadConfig(modules, cfgfile, cfg, NULL) < 0) {
        return (OS_INVALID);
    }

    return (1);
}

/* Free the remote configuration */
void FreeRemotedConfig(remoted *cfg)
{
    int i = 0;

    if (cfg->port) {
        while (cfg->port[i]) {
            free(cfg->port[i]);
            i++;
        }
        free(cfg->port);
        cfg->port = NULL;
    }

    if (cfg->lip) {
        i = 0;
        while (cfg->lip[i]) {
            free(cfg->lip[i]);
            i++;
        }
        free(cfg->lip);
        cfg->lip = NULL;
    }

    free(cfg->conn);
    free(cfg->proto);
    free(cfg->ipv6);

    cfg->conn = NULL;
    cfg->proto = NULL;
    cfg->ipv6 = NULL;

    if (cfg->allowips) {
        i = 0;
        while (cfg->allowips[i]) {
            free(cfg->allowips[i]->ip);
            free(cfg->allowips[i]);
            i++;
        }
        free(cfg->allowips);
        cfg->allowips = NULL;
    }

    if (cfg->denyips) {
        i = 0;
        while (cfg->denyips[i]) {
            free(cfg->denyips[i]->ip);
            free(cfg->denyips[i]);
            i++;
        }
        free(cfg->denyips);
        cfg->denyips = NULL;
    }
}

