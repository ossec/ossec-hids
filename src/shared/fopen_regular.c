/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

#ifndef WIN32

/* Open path for reading, accepting only a regular file.
 *
 * O_NONBLOCK keeps a FIFO without a writer from hanging open(2);
 * O_NOCTTY keeps a planted tty from becoming the controlling terminal.
 * After fstat() confirms S_ISREG, O_NONBLOCK is cleared so reads behave
 * normally. Non-regular files return NULL with errno EINVAL.
 *
 * Own translation unit so callers do not pull file_op.o's __local_name.
 */
FILE *fopen_regular(const char *path)
{
    int fd;
    int flags;
    int oflags;
    int saved_errno;
    struct stat st;
    FILE *fp;

    oflags = O_RDONLY | O_NONBLOCK;
#ifdef O_NOCTTY
    oflags |= O_NOCTTY;
#endif

    fd = open(path, oflags);
    if (fd < 0) {
        return (NULL);
    }

    if (fstat(fd, &st) == -1) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return (NULL);
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return (NULL);
    }

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
    if (fp == NULL) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return (NULL);
    }

    return (fp);
}

#endif /* !WIN32 */
