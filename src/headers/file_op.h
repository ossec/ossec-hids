/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle operation with files */

#ifndef __FILE_H
#define __FILE_H

#include <time.h>
#include <stdbool.h>
#define OS_PIDFILE "/var/run"

/* Set the program name - must be done before *anything* else */
void OS_SetName(const char *name) __attribute__((nonnull));

time_t File_DateofChange(const char *file) __attribute__((nonnull));

int IsDir(const char *file) __attribute__((nonnull));

int CreatePID(const char *name, int pid) __attribute__((nonnull));

char *GetRandomNoise();

int DeletePID(const char *name) __attribute__((nonnull));

int MergeFiles(const char *finalpath, char **files) __attribute__((nonnull));

int MergeAppendFile(const char *finalpath, const char *files) __attribute__((nonnull(1)));

int UnmergeFiles(const char *finalpath, const char *optdir) __attribute__((nonnull(1)));

/* Daemonize a process */
void goDaemon(void);

/* Daemonize a process without closing stdin/stdout/stderr */
void goDaemonLight(void);

/* Not really a file operation, but returns the uname */
char *getuname(void);

/* Return basename of path */
char *basename_ex(char *path) __attribute__((nonnull));

/* Rename file or directory */
int rename_ex(const char *source, const char *destination) __attribute__((nonnull));

/* Create temporary file */
int mkstemp_ex(char *tmp_path) __attribute__((nonnull));

/* Checks for Windows Vista */
#ifdef WIN32
int checkVista();
extern int isVista;

/* Rewrite '\\' to '/' in place so FIM paths, ignores, and alerts share one form. */
void os_normalize_path(char *path);

/* Expand * and ? in a Windows path (FindFirstFile, one path component at a
 * time so directory wildcards work). Returns a NULL-terminated list of
 * strdup'd paths; caller frees each entry and the array. Returns NULL if
 * nothing matched.
 */
char **expand_win32_wildcards(const char *path);
#endif

int w_ref_parent_folder(const char *path);

/* 1 when path is a UNC path (\\server, \\?\UNC\, \\.\pipe, or //server)
 * or, on Windows, a drive letter that is currently a mapped network drive.
 * \\?\C:\ is a local extended path and is allowed.
 */
int os_win_network_path(const char *path);

void remove_control_characters(char *str);

/* When preserve_nl is non-zero, '\\n' and '\\t' are kept (syscheck
 * report_changes / ACL framing). Other C0 and DEL are still removed. */
void remove_control_characters_ex(char *str, int preserve_nl);

/* True for local "syscheck" / "syscheck-registry", or the module after the
 * last "->" in an agent location ("(name) ip->syscheck"). */
int OS_IsSyscheckLocation(const char *location);

bool is_control_character(char c);
#endif /* __FILE_H */
