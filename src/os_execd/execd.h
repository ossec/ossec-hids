/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EXECD_H
#define _EXECD_H

#ifndef ARGV0
#define ARGV0 "ossec-execd"
#endif

/* Add/delete arguments for the commands */
#define ADD_ENTRY       "add"
#define DELETE_ENTRY    "delete"

/* Maximum number of active responses active */
#define MAX_AR      64

/* Maximum number of command arguments */
#define MAX_ARGS    32

/* Execd select timeout -- in seconds */
#define EXECD_TIMEOUT   90

extern int repeated_offenders_timeout[];

/** Function prototypes **/

void WinExecdRun(char *exec_msg);
int ReadExecConfig(void);
char *GetCommandbyName(const char *name, int *timeout) __attribute__((nonnull));
pid_t ExecCmd(char *const *cmd) __attribute__((nonnull));
void ExecCmd_Win32(char *cmd);
int ExecdConfig(const char *cfgfile) __attribute__((nonnull));
int WinExecd_Start(void);
void WinTimeoutRun(int timeout);

/* Timeout data structure */
typedef struct _timeout_data {
    time_t time_of_addition;
    int time_to_block;
    char **command;
    pid_t delete_pid;   /* The "delete" command, once it has been started */
} timeout_data;

void FreeTimeoutEntry(timeout_data *timeout_entry);

/* 1 if ip is a literal address and dst holds its canonical text.
 * Host names, "-", CIDR, and a leading "!" return 0.
 */
int CanonicalIP(const char *ip, char *dst, size_t dstlen);

/* Start "delete" for entries that have timed out. An entry stays on the
 * list, with delete_pid set, until that child is reaped.
 */
int ExecdTimeoutLaunchDeletes(OSList *timeout_list, time_t now,
                              int *childcount);

/* Drop the entry whose delete_pid is pid. Returns 1 if one was removed. */
int ExecdTimeoutReapDelete(OSList *timeout_list, pid_t pid);

/* Returns 1 if request is incomplete or already on the timeout list.
 * childcount, when not NULL, is decremented if this call waits out a
 * "delete" that was still running for the same command and address.
 */
int ExecdTimeoutDupCheck(OSList *timeout_list, char **timeout_args,
                         time_t curr_time, OSHash *repeated_hash,
                         int *childcount);

#endif

