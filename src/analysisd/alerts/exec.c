/* @(#) $Id: ./src/analysisd/alerts/exec.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic e-mailing operations */


#include "shared.h"
#include "rules.h"
#include "alerts.h"
#include "config.h"
#include "active-response.h"

#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_execd/execd.h"

#include "eventinfo.h"


/* OS_Exec v0.1
 */
void OS_Exec(int *execq, int *arq, Eventinfo *lf, active_response *ar)
{
    char exec_msg[OS_SIZE_1024 + 1];
    char *ip;
    char *user;
    char *filename;
    int do_free_filename = 0;

    ip = user = filename = "-";

    /* Cleaning the IP */
    if(lf->srcip && (ar->ar_cmd->expect & SRCIP)) {
        if(strncmp(lf->srcip, "::ffff:", 7) == 0) {
            ip = lf->srcip + 7;
        } else {
            ip = lf->srcip;
        }

        /* Checking if IP is to ignored */
        if(Config.white_list) {
            if(OS_IPFoundList(ip, Config.white_list)) {
                return;
            }
        }

        /* Checking if it is a hostname */
        if(Config.hostname_white_list) {
            int srcip_size;
            OSMatch **wl;

            srcip_size = strlen(ip);

            wl = Config.hostname_white_list;
            while(*wl) {
                if(OSMatch_Execute(ip, srcip_size, *wl)) {
                    return;
                }
                wl++;
            }
        }
    }

    /* Getting username */
    if(lf->dstuser && (ar->ar_cmd->expect & USERNAME)) {
        user = lf->dstuser;
    }

    /* Get the filename */
    if(lf->filename && (ar->ar_cmd->expect & FILENAME)) {
        filename = os_shell_escape(lf->filename);
        do_free_filename = 1;
    }


    /* active response on the server.
     * The response must be here if the ar->location is set to AS
     * or the ar->location is set to local (REMOTE_AGENT) and the
     * event location is from here.
     */
    if((ar->location & AS_ONLY) ||
            ((ar->location & REMOTE_AGENT) && (lf->location[0] != '(')) ) {
        if(!(Config.ar & LOCAL_AR)) {
            return;
        }

        snprintf(exec_msg, OS_SIZE_1024,
                 "%s %s %s %d.%ld %d %s %s",
                 ar->name,
                 user,
                 ip,
                 lf->time,
                 __crt_ftell,
                 lf->generated_rule->sigid,
                 lf->location,
                 filename);

        if(OS_SendUnix(*execq, exec_msg, 0) < 0) {
            merror("%s: Error communicating with execd.", ARGV0);
        }
    }


    /* Active response to the forwarder */
    else if((Config.ar & REMOTE_AR)) {
        int rc;
        /*If lf->location start with a (  was generated by remote agent and its ID is included in lf->location
        	if missing then it must of been generated by the local analysisd so prepend a false id tag */
        if(lf->location[0] == '(') {
            snprintf(exec_msg, OS_SIZE_1024,
                     "%s %c%c%c %s %s %s %s %d.%ld %d %s %s",
                     lf->location,
                     (ar->location & ALL_AGENTS) ? ALL_AGENTS_C : NONE_C,
                     (ar->location & REMOTE_AGENT) ? REMOTE_AGENT_C : NONE_C,
                     (ar->location & SPECIFIC_AGENT) ? SPECIFIC_AGENT_C : NONE_C,
                     ar->agent_id != NULL ? ar->agent_id : "(null)",
                     ar->name,
                     user,
                     ip,
                     lf->time,
                     __crt_ftell,
                     lf->generated_rule->sigid,
                     lf->location,
                     filename);
        } else {
            snprintf(exec_msg, OS_SIZE_1024,
                     "(local_source) %s %c%c%c %s %s %s %s %d.%ld %d %s %s",
                     lf->location,
                     (ar->location & ALL_AGENTS) ? ALL_AGENTS_C : NONE_C,
                     (ar->location & REMOTE_AGENT) ? REMOTE_AGENT_C : NONE_C,
                     (ar->location & SPECIFIC_AGENT) ? SPECIFIC_AGENT_C : NONE_C,
                     ar->agent_id != NULL ? ar->agent_id : "(null)",
                     ar->name,
                     user,
                     ip,
                     lf->time,
                     __crt_ftell,
                     lf->generated_rule->sigid,
                     lf->location,
                     filename);
        }

        if((rc = OS_SendUnix(*arq, exec_msg, 0)) < 0) {
            if(rc == OS_SOCKBUSY) {
                merror("%s: AR socket busy.", ARGV0);
            } else {
                merror("%s: AR socket error (shutdown?).", ARGV0);
            }
            merror("%s: Error communicating with ar queue (%d).", ARGV0, rc);
        }
    }

    // Clean up Memory
    if ( filename != NULL && do_free_filename == 1 ) {
        free(filename);
    }

    return;
}

/* EOF */
