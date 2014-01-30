/* @(#) $Id: ./src/logcollector/logcollector.h, 2012/03/28 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __LOGREADER_H

#define __LOGREADER_H

#ifndef ARGV0
#define ARGV0 "ossec-logcollector"
#endif


#include "shared.h"
#include "config/localfile-config.h"
#include "config/config.h"




/*** Function prototypes ***/


/* Read logcollector config */
int LogCollectorConfig(char * cfgfile, int accept_remote);

/* Stary log collector daemon */
void LogCollectorStart();

/* Handle files */
int handle_file(int i, int do_fseek, int do_log);

/* Read syslog file */
void *read_syslog(int pos, int *rc, int drop_it);

/* Read snort full file */
void *read_snortfull(int pos, int *rc, int drop_it);

/* Read ossec alert file */
void *read_ossecalert(int pos, int *rc, int drop_it);

/* Read nmap grepable format */
void *read_nmapg(int pos, int *rc, int drop_it);

/* Read mysql log format */
void *read_mysql_log(int pos, int *rc, int drop_it);

/* Read mysql log format */
void *read_mssql_log(int pos, int *rc, int drop_it);

/* Read postgresql log format */
void *read_postgresql_log(int pos, int *rc, int drop_it);

/* read multi line logs. */
void *read_multiline(int pos, int *rc, int drop_it);

/* Read DJB multilog format */
/* Initializes multilog. */
int init_djbmultilog(int pos);
void *read_djbmultilog(int pos, int *rc, int drop_it);


/* Read events from output of command */
void *read_command(int pos, int *rc, int drop_it);
void *read_fullcommand(int pos, int *rc, int drop_it);


#ifdef WIN32
/* Windows only */
void win_startel();
void win_readel();
void win_read_vista_sec();
void win_start_event_channel(char *evt_log, char future, char *query);
#endif


/*** Global variables ***/


int loop_timeout;
int logr_queue;
int open_file_attempts;
logreader *logff;


#endif
