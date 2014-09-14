/* @(#) $Id: ./src/headers/read-agents.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CRAGENT_H
#define __CRAGENT_H


/* Unique key for each agent. */
typedef struct _agent_info
{
    char *last_keepalive;
    char *syscheck_time;
    char *syscheck_endtime;
    char *rootcheck_time;
    char *rootcheck_endtime;
    char *os;
    char *version;
}agent_info;


/* Print syscheck DB (of modified files) */
int print_syscheck(char *sk_name, char *sk_ip, char *fname, int print_registry,
                   int all_files, int csv_output, int update_counter);

/* Print rootcheck DB */
int print_rootcheck(char *sk_name, char *sk_ip, char *fname, int resolved,
                    int csv_output, int show_last);

/* Delete syscheck DB */
int delete_syscheck(char *sk_name, char *sk_ip, int full_delete);

/* Delete rootcheck DB */
int delete_rootcheck(char *sk_name, char *sk_ip, int full_delete);

/* Delete agent information */
int delete_agentinfo(char *name);

/* Get all available agents */
char **get_agents(int flag);

/* Free the agent list */
void free_agents(char **agent_list);

/* Prints the text representation of the agent status */
char *print_agent_status(int status);

/* Gets the status of an agent, based on the name/IP */
int get_agent_status(char *agent_name, char *agent_ip);

/* Get information from an agent */
agent_info *get_agent_info(char *agent_name, char *agent_ip);

/*
 * Connects to remoted to be able to send messages to the agents.
 * Returns the socket on success or -1 on failure.
 */
int connect_to_remoted();

/* Sends a message to an agent and returns -1 on error */
int send_msg_to_agent(int msocket, char *msg, char *agt_id, char *exec);




#define GA_NOTACTIVE    2
#define GA_ACTIVE       3
#define GA_ALL          5
#define GA_ALL_WSTATUS  7

/* Status */
#define GA_STATUS_ACTIVE    12
#define GA_STATUS_NACTIVE   13
#define GA_STATUS_INV       14



#endif
