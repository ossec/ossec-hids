/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */


#include "shared.h"
#include "eventinfo.h"
#include "config.h"




/* OSSECAlert decoder init */
void *OSSECAlert_Decoder_Init()
{
    debug1("%s: Initializing OSSECAlert decoder.", ARGV0);


    /* There is nothing else to do over here */
    return(NULL);
}



#define oa_strchr(x,y,z) z = strchr(x,y); if(!z){ return(NULL); }

/* OSSECAlert decoder 
 * Will extract the rule_id and point back to the original rule.
 * Will also extract srcip and username if available.
 * Examples:
 * 
 */                             
void *OSSECAlert_Decoder_Exec(Eventinfo *lf)
{
    char *oa_id = 0;
    char *oa_location;
    char *oa_val;
    char oa_newlocation[256];
    char agent_file[OS_SIZE_1024 +1];
    char tmpstr_buffer[4096 +1];
    char *tmp_str = NULL;
    void *rule_pointer;
    FILE *fp;


    lf->decoder_info->type = OSSEC_ALERT;


    /* Checking the alert level. */
    if(strncmp("Alert Level: ", lf->log, 12) != 0 &&
       strncmp("ossec: Alert Level:", lf->log, 18) != 0)
    {
        return(NULL);
    }

    
    /* Going past the level. */
    oa_strchr(lf->log, ';', tmp_str);
    tmp_str++;


    /* Getting rule id. */
    oa_strchr(tmp_str, ':', tmp_str);
    tmp_str++;
    if(*tmp_str != ' ')
    {
        return(NULL);
    }    
    tmp_str++;

    
    /* Getting id. */
    oa_id = tmp_str;
    oa_strchr(tmp_str, ' ', tmp_str);
    *tmp_str = '\0';


    /* Getting rule structure. */
    rule_pointer = OSHash_Get(Config.g_rules_hash, oa_id);
    if(!rule_pointer)
    {
        *tmp_str = ' ';
        merror("%s: WARN: Rule id '%s' not found internally: %s", ARGV0, oa_id, lf->log);
        *tmp_str = ' ';
        return(NULL);
    }
    *tmp_str = ' ';
    oa_strchr(tmp_str, ';', tmp_str);
    tmp_str++;




    /* Checking location. */
    if(strncmp(" Location: ", tmp_str, 11) != 0)
    {
        return(NULL);
    }
    tmp_str+=11;


    /* Setting location; */
    oa_location = tmp_str;
    

    oa_strchr(tmp_str, ';', tmp_str);
    *tmp_str = '\0';



    /* Setting new location. */
    oa_newlocation[255] = '\0';
    agent_file[OS_SIZE_1024] = '\0';

    
    snprintf(agent_file, OS_SIZE_1024, "%s/%s->%s",
             AGENTINFO_DIR, lf->hostname, lf->location);

    snprintf(oa_newlocation, 255, "%s|%s", lf->location, oa_location);
    free(lf->location);
    os_strdup(oa_newlocation, lf->location);
    lf->hostname = lf->location;



    /* Writting to the agent file */
    fp = fopen(agent_file, "w");
    if(fp)
    {
        fprintf(fp, "%s\n", "Remote Syslog");
        fclose(fp);
    }


    *tmp_str = ';';
    tmp_str++;




    /* Getting additional fields. */
    while((*tmp_str == ' ') && (tmp_str[1] != ' '))
    {
        tmp_str++;
        oa_val = tmp_str;

        tmp_str = strchr(tmp_str, ';');
        if(!tmp_str)
        {
            return(NULL);
        }
        *tmp_str = '\0';

        if(strncmp(oa_val, "srcip: ", 7) == 0)
        {
            os_strdup(oa_val + 7, lf->srcip);
            if(!lf->srcgeoip && lf->srcip)
            {
                lf->srcgeoip = GetGeoInfobyIP(lf->srcip);
            }
        }
        if(strncmp(oa_val, "user: ", 6) == 0)
        {
            os_strdup(oa_val + 6, lf->dstuser);
        }

        *tmp_str = ';';
        tmp_str++;
    }
    

    /* Removing space. */
    while(*tmp_str == ' ')
        tmp_str++;
    

    /* Creating new full log. */
    tmpstr_buffer[0] = '\0';
    tmpstr_buffer[4095] = '\0';
    strncpy(tmpstr_buffer, tmp_str, 4094);

    free(lf->full_log);
    lf->full_log = NULL;
    os_strdup(tmpstr_buffer, lf->full_log);
    lf->log = lf->full_log;
    

    /* Rule that generated. */
    lf->generated_rule = rule_pointer;


    return(NULL);
}

/* END Decoder */
