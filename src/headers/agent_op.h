/* @(#) $Id: ./src/headers/agent_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __AGENT_OP_H
#define __AGENT_OP_H



/** Checks if syscheck is to be executed/restarted.
 *  Returns 1 on success or 0 on failure (shouldn't be executed now).
 */
int os_check_restart_syscheck() ;


/** Sets syscheck to be restarted.
 *  Returns 1 on success or 0 on failure.
 */
int os_set_restart_syscheck();


/** char *os_read_agent_name()
 *  Reads the agent name for the current agent.
 *  Returns NULL on error.
 */
char *os_read_agent_name();


/** char *os_read_agent_ip()
 *  Reads the agent ip for the current agent.
 *  Returns NULL on error.
 */
char *os_read_agent_ip();


/** char *os_read_agent_id()
 *  Reads the agent id for the current agent.
 *  Returns NULL on error.
 */
char *os_read_agent_id();

/* cmoraes: added */

/** char *os_read_agent_profile()
 *  Reads the agent profile name for the current agent.
 *  Returns NULL on error.
 */
char *os_read_agent_profile();


/** int os_write_agent_info(char *agent_name, char *agent_id)
 *  Writes the agent info inside the queue, for the other processes to read.
 *  Returns 1 on success or <= 0 on failure.
 */
int os_write_agent_info(char *agent_name, char *agent_id,
                        char *cfg_profile_name);               /*cmoraes*/


int os_agent_config_changed();


#endif
/* EOF */
