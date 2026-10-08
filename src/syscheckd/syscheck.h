/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __SYSCHECK_H
#define __SYSCHECK_H

#include "config/syscheck-config.h"
#define MAX_LINE PATH_MAX+256

/* Notify list size */
#define NOTIFY_LIST_SIZE    32

/* Global config */
extern syscheck_config syscheck;

/** Function Prototypes **/

/* Check the integrity of the files against the saved database */
void run_check(void);

/* Run run_check periodically */
void start_daemon(void) __attribute__((noreturn));

/* Read the XML config */
int Read_Syscheck_Config(const char *cfgfile) __attribute__((nonnull));

/* Create the database */
int create_db(void);

/* Check database for changes */
int run_dbcheck(void);

/* Scan directory */
int read_dir(const char *dir_name, int opts, OSMatch *restriction);

/* Scan a single path (file, or directory via read_dir). */
int read_file(const char *file_name, int opts, OSMatch *restriction);


/* Check the registry for changes */
void os_winreg_check(void);

/* Start real time */
int realtime_start(void);

/* Add a directory to real time monitoring.
 * opts: syscheck directory options (Windows uses CHECK_ATTRS for the
 * attribute notify mask; ignored on other platforms).
 */
int realtime_adddir(const char *dir, int opts) __attribute__((nonnull(1)));

/* Process real time queue */
int realtime_process(void);

/* Queue a realtime path. The checksum runs after a short delay.
 * A failed read stays queued until it succeeds or the file is gone.
 */
void realtime_enqueue(const char *file_name);

/* Run realtime checksums whose delay has elapsed. */
void realtime_pending_process(void);

/* Milliseconds until the next queued realtime checksum, or -1 if idle. */
int realtime_pending_ms(void);

/* Suppress c_read_file warnings while a realtime retry is in progress. */
void c_read_set_quiet(int quiet);

/* When set, a missing path returns -1 without sending the delete alert.
 * The realtime queue confirms the path is still gone before it alerts. */
void c_read_defer_missing_alert(int defer);

/* Process the content of the file changes */
char *seechanges_addfile(const char *filename) __attribute__((nonnull));

/* Get checksum changes.
 * Returns 0 on success, -1 if missing (delete alerted, unless the
 * realtime queue deferred it), -2 if metadata or checksum read failed
 * (caller should skip without alerting).
 */
int c_read_file(const char *file_name, const char *oldsum, char *newsum) __attribute__((nonnull));

int send_syscheck_msg(const char *msg) __attribute__((nonnull));
int send_rootcheck_msg(const char *msg) __attribute__((nonnull));

#endif

