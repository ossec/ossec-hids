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

int GlobalConfInto(_Config *config, const char *cfgfile)
{
    int modules = 0;

    if (!config) {
        return (OS_INVALID);
    }

    /* Default values */
    config->logall = 0;
    config->logall_json = 0;
    config->stats = 4;
    config->integrity = 8;
    config->rootcheck = 8;
    config->hostinfo = 8;
    config->prelude = 0;
    config->zeromq_output = 0;
    config->zeromq_output_uri = NULL;
    config->zeromq_output_server_cert = NULL;
    config->zeromq_output_client_cert = NULL;
    config->jsonout_output = 0;
    config->memorysize = 8192;
    config->mailnotify = -1;
    config->keeplogdate = 0;
    config->syscheck_alert_new = 0;
    config->syscheck_auto_ignore = 1;
    config->ar = 0;

    config->syscheck_ignore = NULL;
    config->allow_list = NULL;
    config->hostname_allow_list = NULL;

    /* Default actions -- only log above level 1 */
    config->mailbylevel = 7;
    config->logbylevel  = 1;

    config->custom_alert_output = 0;
    config->custom_alert_output_format = NULL;

    config->includes = NULL;
    config->lists = NULL;
    config->decoders = NULL;

    modules |= CGLOBAL;
    modules |= CRULES;
    modules |= CALERTS;

    /* Read config */
    if (ReadConfig(modules, cfgfile, config, NULL) < 0) {
        return (OS_INVALID);
    }

    /* Minimum memory size */
    if (config->memorysize < 2048) {
        config->memorysize = 2048;
    }

    return (0);
}

int GlobalConf(const char *cfgfile)
{
    return (GlobalConfInto(&Config, cfgfile));
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
