/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Functions to handle the configuration files */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "analysisd.h"
#include "config.h"

long int __crt_ftell; /* Global ftell pointer */
_Config Config;       /* Global Config structure */

int GlobalConf(const char *cfgfile)
{
    int modules = 0;

    /* Default values */
    Config.logall = 0;
    Config.logall_json = 0;
    Config.stats = 4;
    Config.integrity = 8;
    Config.rootcheck = 8;
    Config.hostinfo = 8;
    Config.prelude = 0;
    Config.zeromq_output = 0;
    Config.zeromq_output_uri = NULL;
    Config.zeromq_output_server_cert = NULL;
    Config.zeromq_output_client_cert = NULL;
    Config.jsonout_output = 0;
    Config.memorysize = 8192;
    Config.mailnotify = -1;
    Config.keeplogdate = 0;
    Config.syscheck_alert_new = 0;
    Config.syscheck_auto_ignore = 1;
    Config.ar = 0;

    Config.syscheck_ignore = NULL;
    Config.allow_list = NULL;
    Config.hostname_allow_list = NULL;

    /* Default actions -- only log above level 1 */
    Config.mailbylevel = 7;
    Config.logbylevel  = 1;

    Config.custom_alert_output = 0;
    Config.custom_alert_output_format = NULL;

    Config.includes = NULL;
    Config.lists = NULL;
    Config.decoders = NULL;

    modules |= CGLOBAL;
    modules |= CRULES;
    modules |= CALERTS;

    /* Read config */
    if (ReadConfig(modules, cfgfile, &Config, NULL) < 0) {
        return (OS_INVALID);
    }

    /* Minimum memory size */
    if (Config.memorysize < 2048) {
        Config.memorysize = 2048;
    }

    return (0);
}

/* Free a NULL-terminated array of strings */
static void free_str_array(char **array)
{
    int i = 0;
    if (array) {
        while (array[i]) {
            free(array[i]);
            i++;
        }
        free(array);
    }
}

/* Free the Config structure */
void FreeConfig(_Config *config)
{
    int i;
    if (!config) {
        return;
    }

    free(config->prelude_profile);
    free(config->geoipdb_file);
    free(config->zeromq_output_uri);
    free(config->zeromq_output_server_cert);
    free(config->zeromq_output_client_cert);
    free(config->custom_alert_output_format);
    free(config->md5_allowlist);

    free_str_array(config->syscheck_ignore);
    free_str_array(config->hostname_allow_list);
    free_str_array(config->includes);
    free_str_array(config->lists);
    free_str_array(config->decoders);

    if (config->allow_list) {
        for (i = 0; config->allow_list[i]; i++) {
            free(config->allow_list[i]);
        }
        free(config->allow_list);
    }

#ifdef LIBGEOIP_ENABLED
    free(config->geoip_db_path);
    free(config->geoip6_db_path);
#endif

    /* Reset pointers to NULL to prevent double-free if called again */
    config->prelude_profile = NULL;
    config->geoipdb_file = NULL;
    config->zeromq_output_uri = NULL;
    config->zeromq_output_server_cert = NULL;
    config->zeromq_output_client_cert = NULL;
    config->custom_alert_output_format = NULL;
    config->md5_allowlist = NULL;
    config->syscheck_ignore = NULL;
    config->hostname_allow_list = NULL;
    config->includes = NULL;
    config->lists = NULL;
    config->decoders = NULL;
    config->allow_list = NULL;
#ifdef LIBGEOIP_ENABLED
    config->geoip_db_path = NULL;
    config->geoip6_db_path = NULL;
#endif
}
