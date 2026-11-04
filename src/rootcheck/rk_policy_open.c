/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"

int rk_fopen_policy_refused = 0;

int rk_policy_stat_ok(const struct stat *st)
{
    if (st == NULL) {
        return (0);
    }
    if (!S_ISREG(st->st_mode) || (st->st_uid != 0) ||
            (st->st_mode & (S_IWGRP | S_IWOTH))) {
        return (0);
    }
    return (1);
}

#if defined(OSSECHIDS) && !defined(CLIENT) && !defined(WIN32)
#include <fcntl.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif

/* Open a policy file (rootkit_files, rootkit_trojans or system_audit).
 * Its entries choose which files we open and match as root, and the
 * answers go where the whole ossec group can read them. The policies live
 * in etc/shared, which that group can write to, so only accept a file
 * that nobody but root can have written. Check the descriptor, not the
 * name, so the file can't be swapped in between (ANT-2026-B5Y9PIU1).
 * Not on an agent: there ossec-agentd writes them, as sent by the manager.
 */
FILE *rk_fopen_policy(const char *file)
{
    int fd;
    int flags;
    int saved_errno;
    FILE *fp;
    struct stat statbuf;

    rk_fopen_policy_refused = 0;

    if (file == NULL) {
        errno = EINVAL;
        return (NULL);
    }

    fd = open(file, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            merror("%s: ERROR: Ignoring '%s': policy path must not be a "
                   "symlink.", ARGV0, file);
            rk_fopen_policy_refused = 1;
            errno = EACCES;
        }
        return (NULL);
    }

    if ((fstat(fd, &statbuf) < 0) || !rk_policy_stat_ok(&statbuf)) {
        merror("%s: ERROR: Ignoring '%s': it must be a regular file, owned "
               "by root and not writable by group or others.", ARGV0, file);
        close(fd);
        rk_fopen_policy_refused = 1;
        errno = EACCES;
        return (NULL);
    }

    /* Match fopen_regular(): clear O_NONBLOCK once the file is accepted. */
    flags = fcntl(fd, F_GETFL);
    if (flags != -1 && (flags & O_NONBLOCK)) {
        if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
            saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return (NULL);
        }
    }

    fp = fdopen(fd, "r");
    if (!fp) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }

    return (fp);
}

#else

FILE *rk_fopen_policy(const char *file)
{
    rk_fopen_policy_refused = 0;

    if (file == NULL) {
        errno = EINVAL;
        return (NULL);
    }
    return (fopen(file, "r"));
}

#endif
