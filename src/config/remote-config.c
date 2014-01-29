/*   $OSSEC, remote-config.c, v0.3, 2005/11/09, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "remote-config.h"


/* Read_Remote: Reads remote config
 */
int Read_Remote(XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    int pl = 0;

    int allow_size = 1;
    int deny_size = 1;
    remoted *logr;

    /*** XML Definitions ***/

    /* Allowed and denied IPS */
    char *xml_allowips = "allowed-ips";
    char *xml_denyips = "denied-ips";

    /* Remote options */
    char *xml_remote_port = "port";
    char *xml_remote_proto = "protocol";
    char *xml_remote_ipv6 = "ipv6";
    char *xml_remote_connection = "connection";
    char *xml_remote_lip = "local_ip";

    logr = (remoted *)d1;

    /* Getting allowed-ips */
    if(logr->allowips)
    {
        while(logr->allowips[allow_size -1])
            allow_size++;
    }

    /* Getting denied-ips */
    if(logr->denyips)
    {
        while(logr->denyips[deny_size -1])
            deny_size++;
    }


    /* conn and port must not be null */
    if(!logr->conn)
    {
        os_calloc(1, sizeof(int), logr->conn);
        logr->conn[0] = 0;
    }
    if(!logr->port)
    {
        os_calloc(1, sizeof(int), logr->port);
        logr->port[0] = 0;
    }
    if(!logr->proto)
    {
        os_calloc(1, sizeof(int), logr->proto);
        logr->proto[0] = 0;
    }
    if(!logr->ipv6)
    {
        os_calloc(1, sizeof(int), logr->ipv6);
        logr->ipv6[0] = 0;
    }
    if(!logr->lip)
    {
        os_calloc(1, sizeof(char *), logr->lip);
        logr->lip[0] = NULL;
    }


    /* Cleaning */
    while(logr->conn[pl] != 0)
        pl++;


    /* Adding space for the last null connection/port */
    logr->port = realloc(logr->port, sizeof(int)*(pl +2));
    logr->conn = realloc(logr->conn, sizeof(int)*(pl +2));
    logr->proto = realloc(logr->proto, sizeof(int)*(pl +2));
    logr->ipv6 = realloc(logr->ipv6, sizeof(int)*(pl +2));
    logr->lip = realloc(logr->lip, sizeof(char *)*(pl +2));
    if(!logr->port || !logr->conn || !logr->proto || !logr->lip)
    {
        merror(MEM_ERROR, ARGV0);
    }

    logr->port[pl] = 0;
    logr->conn[pl] = 0;
    logr->proto[pl] = 0;
    logr->ipv6[pl] = 0;
    logr->lip[pl] = NULL;

    logr->port[pl +1] = 0;
    logr->conn[pl +1] = 0;
    logr->proto[pl +1] = 0;
    logr->ipv6[pl +1] = 0;
    logr->lip[pl +1] = NULL;

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
        else if(strcasecmp(node[i]->element,xml_remote_connection) == 0)
        {
            if(strcmp(node[i]->content, "syslog") == 0)
            {
                logr->conn[pl] = SYSLOG_CONN;
            }
            else if(strcmp(node[i]->content, "secure") == 0)
            {
                logr->conn[pl] = SECURE_CONN;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcasecmp(node[i]->element,xml_remote_port) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            logr->port[pl] = atoi(node[i]->content);

            if(logr->port[pl] <= 0 || logr->port[pl] > 65535)
            {
                merror(PORT_ERROR, ARGV0, logr->port[pl]);
                return(OS_INVALID);
            }
        }
        else if(strcasecmp(node[i]->element,xml_remote_proto) == 0)
        {
            if(strcasecmp(node[i]->content, "tcp") == 0)
            {
                logr->proto[pl] = TCP_PROTO;
            }
            else if(strcasecmp(node[i]->content, "udp") == 0)
            {
                logr->proto[pl] = UDP_PROTO;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,
                       node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcasecmp(node[i]->element,xml_remote_ipv6) == 0)
        {
            if(strcasecmp(node[i]->content, "yes") == 0)
            {
                logr->ipv6[pl] = 1;
            }
        }
        else if(strcasecmp(node[i]->element,xml_remote_lip) == 0)
        {
            os_strdup(node[i]->content,logr->lip[pl]);
            if(OS_IsValidIP(logr->lip[pl], NULL) != 1)
            {
                merror(INVALID_IP, ARGV0, node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_allowips) == 0)
        {
            allow_size++;
            logr->allowips =realloc(logr->allowips,sizeof(os_ip *)*allow_size);
            if(!logr->allowips)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_calloc(1, sizeof(os_ip), logr->allowips[allow_size -2]);
            logr->allowips[allow_size -1] = NULL;

            if(!OS_IsValidIP(node[i]->content,logr->allowips[allow_size -2]))
            {
                merror(INVALID_IP, ARGV0, node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_denyips) == 0)
        {
            deny_size++;
            logr->denyips = realloc(logr->denyips,sizeof(os_ip *)*deny_size);
            if(!logr->denyips)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_calloc(1, sizeof(os_ip), logr->denyips[deny_size -2]);
            logr->denyips[deny_size -1] = NULL;
            if(!OS_IsValidIP(node[i]->content, logr->denyips[deny_size -2]))
            {
                merror(INVALID_IP, ARGV0, node[i]->content);
                return(OS_INVALID);
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }

    /* conn must be set */
    if(logr->conn[pl] == 0)
    {
        merror(CONN_ERROR, ARGV0);
        return(OS_INVALID);
    }

    /* Set port in here */
    if(logr->port[pl] == 0)
    {
        if(logr->conn[pl] == SECURE_CONN)
            logr->port[pl] = DEFAULT_SECURE;
        else
            logr->port[pl] = DEFAULT_SYSLOG;
    }

    /* set default protocol */
    if(logr->proto[pl] == 0)
    {
        logr->proto[pl] = UDP_PROTO;
    }

    /* Secure connections only run on UDP */
    if((logr->conn[pl] == SECURE_CONN) && (logr->proto[pl] == TCP_PROTO))
    {
        logr->proto[pl] = UDP_PROTO;
    }

    return(0);
}


/* EOF */
