/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"


/* Read the config file (the localfiles) */
logreader *LogCollectorConfig(const char *cfgfile, int accept_remote)
{
    int modules = 0;
    logreader_config log_config;

    modules |= CLOCALFILE;

    log_config.config = NULL;
    log_config.agent_cfg = 0;
    log_config.accept_remote = accept_remote;

    if (ReadConfig(modules, cfgfile, &log_config, NULL) < 0) {
        return (NULL);
    }

#ifdef CLIENT
    modules |= CAGENT_CONFIG;
    log_config.agent_cfg = 1;
    if (ReadConfig(modules, AGENTCONFIG, &log_config, NULL) < 0) {
        Free_Localfile(log_config.config);
        return (NULL);
    }
    log_config.agent_cfg = 0;
#endif

    return (log_config.config);
}

