/* @(#) $Id: ./src/remoted/main.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "remoted.h"


int main(int argc, char **argv)
{
    int i = 0,c = 0;
    int uid = 0, gid = 0;
    int debug_level = 0;
    int test_config = 0,run_foreground = 0;

    char *cfg = DEFAULTCPATH;
    char *dir = DEFAULTDIR;
    char *user = REMUSER;
    char *group = GROUPGLOBAL;


    /* Setting the name -- must be done ASAP */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vdthfu:g:c:D:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user = optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'c':
                if (!optarg)
                    ErrorExit("%s: -c need an argument", ARGV0);
                cfg = optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
                break;
        }
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0)
    {
        /* Getting debug level */
        debug_level = getDefine_Int("remoted", "debug", 0, 2);
        while(debug_level != 0)
        {
            nowDebug();
            debug_level--;
        }
    }


    debug1(STARTED_MSG,ARGV0);


    /* Return 0 if not configured */
    if(RemotedConfig(cfg, &logr) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* Exit if test_config is set */
    if(test_config)
        exit(0);

    if(logr.conn == NULL)
    {
        /* Not configured. */
        exit(0);
    }

    /* Check if the user and group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR, ARGV0, user, group);


    /* pid before going daemon */
    i = getpid();


    if(!run_foreground)
    {
        nowDaemon();
        goDaemon();
    }


    /* Setting new group */
    if(Privsep_SetGroup(gid) < 0)
            ErrorExit(SETGID_ERROR, ARGV0, group);

    /* Going on chroot */
    if(Privsep_Chroot(dir) < 0)
                ErrorExit(CHROOT_ERROR,ARGV0,dir);


    nowChroot();


    /* Starting the signal manipulation */
    StartSIG(ARGV0);


    /* Creating some randoness  */
    #ifdef __OpenBSD__
    srandomdev();
    #else
    srandom( time(0) + getpid()+ i);
    #endif

    random();


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* Really starting the program. */
    i = 0;
    while(logr.conn[i] != 0)
    {
        /* Forking for each connection handler */
        if(fork() == 0)
        {
            /* On the child */
            debug1("%s: DEBUG: Forking remoted: '%d'.",ARGV0, i);
            HandleRemote(i, uid);
        }
        else
        {
            i++;
            continue;
        }
    }


    /* Done over here */
    return(0);
}


/* EOF */
