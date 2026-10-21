/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

#ifndef WIN32

/* Open a log file for appending. Returns the descriptor, or -1 on error.
 * The logs directory belongs to the ossec user while root writes there too,
 * so a link or a special file left in place of the log must not decide
 * where root appends: only a regular file with a single name is accepted.
 *
 * Lives in its own translation unit so callers (e.g. debug_op) do not pull
 * file_op.o's __local_name definition into binaries that define their own.
 */
int open_log_append(const char *path)
{
    int fd;
    struct stat st;

#ifndef O_NOFOLLOW
    /* Without O_NOFOLLOW we cannot refuse a planted symlink. */
    (void)path;
    errno = ENOTSUP;
    return (-1);
#else
    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK,
              0660);
    if (fd == -1) {
        return (-1);
    }

    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd);
        errno = ELOOP;
        return (-1);
    }

    return (fd);
#endif
}

#endif /* !WIN32 */
