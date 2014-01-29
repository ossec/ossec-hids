/*   $OSSEC, alerts-config.c, v0.1, 2005/04/02, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle the configuration files
 */


#include "shared.h"
#include "global-config.h"


int Read_Alerts(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;

    /* XML definitions */
    char *xml_email_level = "email_alert_level";
    char *xml_log_level = "log_alert_level";

#ifdef GEOIP
    /* GeoIP */
    char *xml_log_geoip = "use_geoip";
#endif

    _Config *Config;

    Config = (_Config *)configp;


    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        /* Mail notification */
        else if(strcmp(node[i]->element, xml_email_level) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            Config->mailbylevel = atoi(node[i]->content);
        }
        /* Log alerts */
        else if(strcmp(node[i]->element, xml_log_level) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            Config->logbylevel  = atoi(node[i]->content);
        }
#ifdef GEOIP
	/* Enable GeoIP */
	else if(strcmp(node[i]->element, xml_log_geoip) == 0)
	{
            if(strcmp(node[i]->content, "yes") == 0)
                { if(Config) Config->loggeoip = 1;}
            else if(strcmp(node[i]->content, "no") == 0)
                {if(Config) Config->loggeoip = 0;}
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

	}
#endif
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }
    return(0);
}


/* EOF */
