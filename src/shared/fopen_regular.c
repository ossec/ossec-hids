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

/* Open path for reading without following any symlink component.
 *
 * Starts at "/" or "." and walks each name with openat(O_NOFOLLOW).
 * Directory components use O_DIRECTORY; the final entry must be a
 * regular file (O_NONBLOCK|O_NOCTTY, then O_NONBLOCK cleared). A
 * symlink anywhere in the path fails with ELOOP (or EINVAL if the
 * final open succeeded on a non-regular file — should not happen with
 * O_NOFOLLOW on a link).
 */
FILE *fopen_regular_nofollow(const char *path)
{
    char pending[PATH_MAX + 1];
    char *cursor;
    char *slash;
    int dirfd = -1;
    int fd = -1;
    int flags;
    int oflags;
    int saved_errno;
    struct stat st;
    FILE *fp;
    size_t n;

    if (path[0] == '\0') {
        errno = EINVAL;
        return (NULL);
    }

    n = strlen(path);
    if (n >= sizeof(pending)) {
        errno = ENAMETOOLONG;
        return (NULL);
    }
    memcpy(pending, path, n + 1);

    if (pending[0] == '/') {
        dirfd = open("/", O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
                     | O_CLOEXEC
#endif
                     );
        cursor = pending + 1;
    } else {
        dirfd = open(".", O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
                     | O_CLOEXEC
#endif
                     );
        cursor = pending;
    }
    if (dirfd < 0) {
        return (NULL);
    }

    while (*cursor != '\0') {
        while (*cursor == '/') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        slash = strchr(cursor, '/');
        if (slash) {
            *slash = '\0';
        }

        if (slash == NULL) {
            /* Final component: regular file, do not follow a link. */
            oflags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
#ifdef O_NOCTTY
            oflags |= O_NOCTTY;
#endif
#ifdef O_CLOEXEC
            oflags |= O_CLOEXEC;
#endif
            fd = openat(dirfd, cursor, oflags);
            saved_errno = errno;
            close(dirfd);
            dirfd = -1;
            if (fd < 0) {
                errno = saved_errno;
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

        /* Intermediate directory: must be a real directory, not a link. */
        fd = openat(dirfd, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW
#ifdef O_CLOEXEC
                    | O_CLOEXEC
#endif
                    );
        saved_errno = errno;
        close(dirfd);
        dirfd = fd;
        if (dirfd < 0) {
            errno = saved_errno;
            return (NULL);
        }

        cursor = slash + 1;
    }

    /* Path ended in a directory (trailing slash) or was "/" / "." alone. */
    if (dirfd >= 0) {
        close(dirfd);
    }
    errno = EINVAL;
    return (NULL);
}

#endif /* !WIN32 */
