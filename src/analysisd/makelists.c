/* @(#) $Id: ./src/analysisd/makelists.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2010 Trend Micro Inc.
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


/* Part of the OSSEC
 * Available at http://www.ossec.net
 */


/* ossec-analysisd.
 * Responsible for correlation and log decoding.
 */
#ifdef ARGV0
    #undef ARGV0
    #define ARGV0 "ossec-testrule"
#endif

#include "shared.h"


/** Local headers **/
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "lists_make.h"

#include "eventinfo.h"
#include "analysisd.h"

#include "picviz.h"



/** External functions prototypes (only called here) **/

/* For config  */
int GlobalConf(char * cfgfile);


/* For Lists */
void Lists_OP_CreateLists();

void makelist_help(const char *prog)
{
    print_out(" ");
    print_out("%s %s - %s (%s)", __ossec_name, __version, __author, __contact);
    print_out("%s", __site);
    print_out(" ");
    print_out("  %s: -[Vhdt] [-u user] [-g group] [-c config] [-D dir]", prog);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode");
    print_out("    -f          Force rebuild of all databases");
    print_out("    -u <user>   Run as 'user'");
    print_out("    -g <group>  Run as 'group'");
    print_out("    -c <config> Read the 'config' file");
    print_out("    -D <dir>    Chroot to 'dir'");
    print_out(" ");
    exit(1);
}

/** int main(int argc, char **argv)
 */
int main(int argc, char **argv)
{
    int c = 0;
    char *dir = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    int uid = 0,gid = 0;
    int force = 0;

    char *cfg = DEFAULTCPATH;

    /* Setting the name */
    OS_SetName(ARGV0);

    thishour = 0;
    today = 0;
    prev_year = 0;
    memset(prev_month, '\0', 4);

    while((c = getopt(argc, argv, "Vdhfu:g:D:c:")) != -1){
        switch(c){
	    case 'V':
		print_version();
		break;
            case 'h':
                makelist_help(ARGV0);
                break;
            case 'd':
                nowDebug();
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
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 'f':
                force = 1;
                break;
            default:
                help(ARGV0);
                break;
        }

    }


    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);


    /* Found user */
    debug1(FOUND_USER, ARGV0);


    /* Reading configuration file */
    if(GlobalConf(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR,ARGV0, cfg);
    }

    debug1(READ_CONFIG, ARGV0);

    /* Setting the group */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    /* Chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    nowChroot();



    /* Createing the lists for use in rules */
    Lists_OP_CreateLists();

    /* Reading the lists */
    {
        char **listfiles;
        listfiles = Config.lists;
        while(listfiles && *listfiles)
        {
            if(Lists_OP_LoadList(*listfiles) < 0)
                ErrorExit(LISTS_ERROR, ARGV0, *listfiles);
            free(*listfiles);
            listfiles++;
        }
        free(Config.lists);
        Config.lists = NULL;
    }

    Lists_OP_MakeAll(force);

    exit(0);
}

/* EOF */
