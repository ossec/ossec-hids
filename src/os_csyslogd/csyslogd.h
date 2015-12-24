/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CSYSLOGD_H
#define _CSYSLOGD_H

#include "config/csyslogd-config.h"

#define OS_CSYSLOGD_MAX_TRIES 10

/** Prototypes **/

/* Read syslog config */
SyslogConfig **OS_ReadSyslogConf(int test_config, const char *cfgfile);

/* Send alerts via syslog */
int OS_Alert_SendSyslog(alert_data *al_data, const SyslogConfig *syslog_config);

/* Database inserting main function */
void OS_CSyslogD(SyslogConfig **syslog_config) __attribute__((noreturn));

/* Conditional Field Formatting */
int field_add_int(char *dest, size_t size, const char *format, const int value );
int field_add_string(char *dest, size_t size, const char *format, const char *value );
int field_add_truncated(char *dest, size_t size, const char *format, const char *value,  int fmt_size );

/** Global variables **/

/* System hostname */
extern char __shost[512];
/* System hostname (full length) */
extern char __shost_long[512];

#endif /* _CSYSLOGD_H */

