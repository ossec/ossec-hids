/* @(#) $Id: ./src/os_dbd/main.c, 2011/09/08 dcid Exp $
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


#ifndef DBD
   #define DBD
#endif

#ifndef ARGV0
   #define ARGV0 "ossec-dbd"
#endif

#include "shared.h"
#include "dbd.h"


/* Prints information regarding enabled databases */
void db_info()
{
    print_out(" ");
    print_out("%s %s - %s", __name, __version, __author);

    #ifdef UMYSQL
    print_out("Compiled with MySQL support.");
    #endif

    #ifdef UPOSTGRES
    print_out("Compiled with PostgreSQL support.");
    #endif

    #if !defined(UMYSQL) && !defined(UPOSTGRES)
    print_out("Compiled without any Database support.");
    #endif

    print_out(" ");
    print_out("%s",__license);

    exit(1);
}



int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    int uid = 0,gid = 0;
    unsigned int d = 0;

    /* Using MAILUSER (read only) */
    char *dir  = DEFAULTDIR;
    char *user = MAILUSER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;


    /* Database Structure */
    DBConfig db_config;
    db_config.error_count = 0;


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "vVdhtfu:g:D:c:")) != -1){
        switch(c){
            case 'V':
                db_info();
                break;
            case 'v':
                db_info();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help(ARGV0);
                break;
        }

    }


    /* Starting daemon */
    debug1(STARTED_MSG, ARGV0);


    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
    {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }


    /* Reading configuration */
    if((c = OS_ReadDBConf(cfg, &db_config)) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* Exit here if test config is set */
    if(test_config)
        exit(0);


    if(!run_foreground)
    {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }



    /* Not configured */
    if(c == 0)
    {
        verbose("%s: Database not configured. Clean exit.", ARGV0);
        exit(0);
    }


    /* Maybe disable this debug? */
    debug1("%s: DEBUG: Connecting to '%s', using '%s', '%s', '%s', %d,'%s'.",
           ARGV0, db_config.host, db_config.user,
           db_config.pass, db_config.db,db_config.port,db_config.sock);


    /* Setting config pointer */
    osdb_setconfig(&db_config);


    /* Getting maximum reconned attempts */
    db_config.maxreconnect = getDefine_Int("dbd",
                                           "reconnect_attempts", 1, 9999);


    /* Connecting to the database */
    while(d <= (db_config.maxreconnect * 10))
    {
        db_config.conn = osdb_connect(db_config.host, db_config.user,
                                      db_config.pass, db_config.db,
                                      db_config.port,db_config.sock);

        /* If we are able to reconnect, keep going */
        if(db_config.conn)
        {
            break;
        }

        d++;
        sleep(d * 60);

    }


    /* If after the maxreconnect attempts, it still didn't work, exit here. */
    if(!db_config.conn)
    {
        merror(DB_CONFIGERR, ARGV0);
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* We must notify that we connected -- easy debugging */
    verbose("%s: Connected to database '%s' at '%s'.",
            ARGV0, db_config.db, db_config.host);


    /* Privilege separation */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);


    /* Now on chroot */
    nowChroot();


    /* Inserting server info into the db */
    db_config.server_id = OS_Server_ReadInsertDB(&db_config);
    if(db_config.server_id <= 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* Read rules and insert into the db */
    if(OS_InsertRulesDB(&db_config) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* Changing user */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    /* Basic start up completed. */
    debug1(PRIVSEP_MSG,ARGV0,dir,user);


    /* Signal manipulation */
    StartSIG(ARGV0);


    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* the real daemon now */
    OS_DBD(&db_config);
    exit(0);
}


/* EOF */
