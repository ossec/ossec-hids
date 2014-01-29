/* @(#) $Id: ./src/os_csyslogd/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "csyslogd.h"
#include "config/global-config.h"
#include "config/config.h"


/** void *OS_SyslogConf(int test_config, char *cfgfile,
                        SyslogConfig **syslog_config)
 * Reads configuration.
 */
void *OS_ReadSyslogConf(char *cfgfile, SyslogConfig **syslog_config)
{
    int modules = 0;
    GeneralConfig gen_config;


    /* Modules for the configuration */
    modules|= CSYSLOGD;
    gen_config.data = syslog_config;


    /* Reading configuration */
    if(ReadConfig(modules, cfgfile, &gen_config, NULL) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfgfile);
        return(NULL);
    }


    syslog_config = gen_config.data;

    return(syslog_config);
}

/* EOF */
