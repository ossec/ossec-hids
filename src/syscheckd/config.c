/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "config/config.h"
#include "os_regex/os_regex.h"

#ifndef WIN32
const char *cfgfile;
#endif

#ifdef WIN32
static char *SYSCHECK_EMPTY[] = { NULL };
#endif


/* Free the syscheck configuration */
void FreeSyscheckConfig(syscheck_config *config)
{
    int i = 0;

    if (config->dir) {
        while (config->dir[i]) {
            free(config->dir[i]);
            i++;
        }
        free(config->dir);
        config->dir = NULL;
    }

    if (config->opts) {
        free(config->opts);
        config->opts = NULL;
    }

    if (config->ignore) {
        i = 0;
        while (config->ignore[i]) {
            free(config->ignore[i]);
            i++;
        }
        free(config->ignore);
        config->ignore = NULL;
    }

    if (config->ignore_regex) {
        i = 0;
        while (config->ignore_regex[i]) {
            OSMatch_FreePattern(config->ignore_regex[i]);
            free(config->ignore_regex[i]);
            i++;
        }
        free(config->ignore_regex);
        config->ignore_regex = NULL;
    }

    if (config->nodiff) {
        i = 0;
        while (config->nodiff[i]) {
            free(config->nodiff[i]);
            i++;
        }
        free(config->nodiff);
        config->nodiff = NULL;
    }

    if (config->nodiff_regex) {
        i = 0;
        while (config->nodiff_regex[i]) {
            OSMatch_FreePattern(config->nodiff_regex[i]);
            free(config->nodiff_regex[i]);
            i++;
        }
        free(config->nodiff_regex);
        config->nodiff_regex = NULL;
    }

    if (config->filerestrict) {
        i = 0;
        while (config->filerestrict[i]) {
            OSMatch_FreePattern(config->filerestrict[i]);
            free(config->filerestrict[i]);
            i++;
        }
        free(config->filerestrict);
        config->filerestrict = NULL;
    }

    free(config->scan_day);
    free(config->scan_time);
    free(config->prefilter_cmd);

    config->scan_day = NULL;
    config->scan_time = NULL;
    config->prefilter_cmd = NULL;

#ifdef WIN32
    if (config->registry) {
        i = 0;
        while (config->registry[i]) {
            free(config->registry[i]);
            i++;
        }
        free(config->registry);
        config->registry = NULL;
    }
#endif
}

int Read_Syscheck_Config(const char *cfgfile, syscheck_config *config)
{
    int modules = 0;

    modules |= CSYSCHECK;

    config->rootcheck      = 0;
    config->disabled       = 0;
    config->skip_nfs       = 0;
    config->scan_on_start  = 1;
    config->time           = SYSCHECK_WAIT * 2;
    config->ignore         = NULL;
    config->ignore_regex   = NULL;
    config->nodiff         = NULL;
    config->nodiff_regex   = NULL;
    config->scan_day       = NULL;
    config->scan_time      = NULL;
    config->dir            = NULL;
    config->opts           = NULL;
    config->realtime       = NULL;
#ifdef WIN32
    config->registry       = NULL;
    config->reg_fp         = NULL;
#endif
    config->prefilter_cmd  = NULL;

    debug2("%s: Reading Configuration [%s]", "syscheckd", cfgfile);

    /* Read config */
    if (ReadConfig(modules, cfgfile, config, NULL) < 0) {
        return (OS_INVALID);
    }

    /* Read shared config */
    modules |= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, config, NULL);


#ifndef WIN32
    /* We must have at least one directory to check */
    if (!config->dir || config->dir[0] == NULL) {
        return (1);
    }
#else
    /* We must have at least one directory or registry key to check. Since
       it's possible on Windows to have syscheck enabled but only monitoring
       either the filesystem or the registry, both lists must be valid,
       even if empty.
     */
    if (!config->dir) {
        config->dir = SYSCHECK_EMPTY;
    }
    if (!config->registry) {
        config->registry = SYSCHECK_EMPTY;
    }
    if ((config->dir[0] == NULL) && (config->registry[0] == NULL)) {
        return (1);
    }
#endif

    return (0);
}

