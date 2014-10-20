/* @(#) $Id: ./src/rootcheck/rootcheck.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Rootcheck v 0.3
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 * http://www.ossec.net/rootcheck/
 *
 */

/* Included from the Rootcheck project */


#include "headers/shared.h"

#include "rootcheck.h"
rkconfig rootcheck;
char **rk_sys_file;
char **rk_sys_name;
int rk_sys_count;
char total_ports_udp[65535 +1];
char total_ports_tcp[65535 +1];

#ifndef ARGV0
#define ARGV0 "rootcheck"
#endif




int rootcheck_init(int test_config)
{
    int c;


    const char *cfg = DEFAULTCPATH;

    /* Zeroing the structure, initializing default values */
    rootcheck.workdir = NULL;
    rootcheck.basedir = NULL;
    rootcheck.unixaudit = NULL;
    rootcheck.ignore = NULL;
    rootcheck.rootkit_files = NULL;
    rootcheck.rootkit_trojans = NULL;
    rootcheck.winaudit = NULL;
    rootcheck.winmalware = NULL;
    rootcheck.winapps = NULL;
    rootcheck.daemon = 1;
    rootcheck.notify = QUEUE;
    rootcheck.scanall = 0;
    rootcheck.readall = 0;
    rootcheck.disabled = 0;
    rootcheck.alert_msg = NULL;
    rootcheck.time = ROOTCHECK_WAIT;


    rootcheck.checks.rc_dev = 1;
    rootcheck.checks.rc_files = 1;
    rootcheck.checks.rc_if = 1;
    rootcheck.checks.rc_pids = 1;
    rootcheck.checks.rc_ports = 1;
    rootcheck.checks.rc_sys = 1;
    rootcheck.checks.rc_trojans = 1;

    #ifdef WIN32

    rootcheck.checks.rc_winaudit = 1;
    rootcheck.checks.rc_winmalware = 1;
    rootcheck.checks.rc_winapps = 1;

    #else

    rootcheck.checks.rc_unixaudit = 1;

    #endif

    /* We store up to 255 alerts in there. */
    os_calloc(256, sizeof(char *), rootcheck.alert_msg);
    c = 0;
    while(c <= 255)
    {
        rootcheck.alert_msg[c] = NULL;
        c++;
    }




    /* Staring message */
    debug1(STARTED_MSG,ARGV0);


    /* Checking if the configuration is present */
    if(File_DateofChange(cfg) < 0)
    {
        merror("%s: Configuration file '%s' not found",ARGV0,cfg);
        return(-1);
    }


    /* Reading configuration  --function specified twice (check makefile) */
    if(Read_Rootcheck_Config(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* If testing config, exit here */
    if(test_config)
        return(0);


    /* Return 1 disables rootcheck */
    if(rootcheck.disabled == 1)
    {
        verbose("%s: Rootcheck disabled. Exiting.", ARGV0);
        return(1);
    }


    /* Checking if Unix audit file is configured. */
    if(!rootcheck.unixaudit)
    {
        #ifndef WIN32
        log2file("%s: System audit file not configured.", ARGV0);
        #endif
    }


    /* Setting default values */
    if(rootcheck.workdir == NULL)
        rootcheck.workdir = DEFAULTDIR;



    /* Start up message */
    #ifdef WIN32
    verbose(STARTUP_MSG, "ossec-rootcheck", getpid());
    #else


    /* Connect to the queue if configured to do so */
    if(rootcheck.notify == QUEUE)
    {
        debug1("%s: Starting queue ...",ARGV0);

        /* Starting the queue. */
        if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH, strerror(errno));

            /* 5 seconds to see if the agent starts */
            sleep(5);
            if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                /* more 10 seconds wait.. */
                merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH, strerror(errno));
                sleep(10);
                if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                    ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQPATH);
            }
        }
    }

    #endif /* Not win32 */


    /* Initializing rk list */
    rk_sys_name = (char **) calloc(MAX_RK_SYS +2, sizeof(char *));
    rk_sys_file = (char **) calloc(MAX_RK_SYS +2, sizeof(char *));
    if(!rk_sys_name || !rk_sys_file)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
    rk_sys_name[0] = NULL;
    rk_sys_file[0] = NULL;



    debug1("%s: DEBUG: Running run_rk_check",ARGV0);
    run_rk_check();

    debug1("%s: DEBUG:  Leaving...",ARGV0);

    return(0);
}

/* EOF */
