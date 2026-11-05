/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * Look directory entries up in the directory that was opened, and do not
 * follow a symlink below a configured directory (ANT-2026-MBH20U16).
 */

#include <errno.h>
#include <string.h>

#include "shared.h"
#include "syscheck.h"

#ifndef WIN32
#include <fcntl.h>

static int open_directory(const char *path)
{
    int fd;

    fd = open(path, O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
              | O_CLOEXEC
#endif
              );
    return (fd);
}

/* Longest configured directory that is a prefix of path. */
static int configured_prefix(const char *path, size_t *len_out)
{
    int i;
    int best = -1;
    size_t best_len = 0;

    if (syscheck.dir == NULL) {
        return (-1);
    }

    for (i = 0; syscheck.dir[i] != NULL; i++) {
        size_t len = strlen(syscheck.dir[i]);

        while (len > 1 && syscheck.dir[i][len - 1] == '/') {
            len--;
        }
        if (len < best_len) {
            continue;
        }
        if (strncmp(path, syscheck.dir[i], len) != 0) {
            continue;
        }
        if (path[len] != '\0' && path[len] != '/') {
            continue;
        }
        best = i;
        best_len = len;
    }

    if (best < 0) {
        return (-1);
    }
    *len_out = best_len;
    return (best);
}

/* Walk path. Intermediate components below the configured directory are
 * opened with O_NOFOLLOW. The final component is lstat'd, and if out_fd
 * is set it is opened (O_NOFOLLOW unless follow_leaf). */
static int walk_monitored(const char *path, int follow_leaf,
                          struct stat *out_st, int *out_fd)
{
    char pending[PATH_MAX + 1];
    char *cursor;
    char *slash;
    size_t prefix = 0;
    size_t n;
    int dirfd = -1;
    int fd = -1;
    int saved_errno;

    if (out_fd) {
        *out_fd = -1;
    }
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return (-1);
    }
    n = strlen(path);
    if (n >= sizeof(pending)) {
        errno = ENAMETOOLONG;
        return (-1);
    }
    memcpy(pending, path, n + 1);

    if (configured_prefix(path, &prefix) >= 0) {
        char saved = pending[prefix];

        pending[prefix] = '\0';
        dirfd = open_directory(pending[0] ? pending : "/");
        pending[prefix] = saved;
        cursor = pending + prefix;
    } else if (pending[0] == '/') {
        dirfd = open_directory("/");
        cursor = pending + 1;
    } else {
        dirfd = open_directory(".");
        cursor = pending;
    }
    if (dirfd < 0) {
        return (-1);
    }

    while (*cursor == '/') {
        cursor++;
    }
    if (*cursor == '\0') {
        if (fstat(dirfd, out_st) < 0) {
            saved_errno = errno;
            close(dirfd);
            errno = saved_errno;
            return (-1);
        }
        close(dirfd);
        return (0);
    }

    for (;;) {
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

        if (strcmp(cursor, "..") == 0) {
            close(dirfd);
            errno = ELOOP;
            return (-1);
        }
        if (cursor[0] == '\0' || strcmp(cursor, ".") == 0) {
            if (slash) {
                cursor = slash + 1;
                continue;
            }
            break;
        }

        if (slash != NULL) {
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
                return (-1);
            }
            cursor = slash + 1;
            continue;
        }

        if (out_fd == NULL) {
            if (fstatat(dirfd, cursor, out_st, AT_SYMLINK_NOFOLLOW) < 0) {
                saved_errno = errno;
                close(dirfd);
                errno = saved_errno;
                return (-1);
            }
            close(dirfd);
            return (0);
        }

        fd = openat(dirfd, cursor,
                    O_RDONLY | O_NONBLOCK | (follow_leaf ? 0 : O_NOFOLLOW)
#ifdef O_NOCTTY
                    | O_NOCTTY
#endif
#ifdef O_CLOEXEC
                    | O_CLOEXEC
#endif
                    );
        saved_errno = errno;
        close(dirfd);
        if (fd < 0) {
            errno = saved_errno;
            return (-1);
        }
        if (fstat(fd, out_st) < 0) {
            saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return (-1);
        }
        if (!S_ISREG(out_st->st_mode)) {
            close(fd);
            errno = EINVAL;
            return (-1);
        }
        {
            int flags = fcntl(fd, F_GETFL);

            if (flags != -1 && (flags & O_NONBLOCK) &&
                    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
                saved_errno = errno;
                close(fd);
                errno = saved_errno;
                return (-1);
            }
        }
        *out_fd = fd;
        return (0);
    }

    close(dirfd);
    errno = EINVAL;
    return (-1);
}

int fim_lstat_entry(DIR *parent, const char *name, const char *path,
                    struct stat *st)
{
    if (parent != NULL && name != NULL) {
        return (fstatat(dirfd(parent), name, st, AT_SYMLINK_NOFOLLOW));
    }
    return (lstat(path, st));
}

int fim_open_entry(DIR *parent, const char *name, const char *path, int flags)
{
    if (parent != NULL && name != NULL) {
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOCTTY
        flags |= O_NOCTTY;
#endif
        return (openat(dirfd(parent), name, flags | O_NOFOLLOW));
    }
    return (open(path, flags));
}

int fim_open_entry_follow(DIR *parent, const char *name, const char *path)
{
    int flags = O_RDONLY | O_NONBLOCK;

#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOCTTY
    flags |= O_NOCTTY;
#endif
    if (parent != NULL && name != NULL) {
        return (openat(dirfd(parent), name, flags));
    }
    return (open(path, flags));
}

DIR *fim_opendir_entry(DIR *parent, const char *name, const char *path)
{
    int fd;
    DIR *dp;

    if (parent == NULL || name == NULL) {
        return (opendir(path));
    }

    fd = openat(dirfd(parent), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW
#ifdef O_CLOEXEC
                | O_CLOEXEC
#endif
                );
    if (fd < 0) {
        return (NULL);
    }
    dp = fdopendir(fd);
    if (dp == NULL) {
        int saved = errno;

        close(fd);
        errno = saved;
    }
    return (dp);
}

int fim_lstat_monitored(const char *path, struct stat *st)
{
    return (walk_monitored(path, 0, st, NULL));
}

FILE *fim_fopen_monitored(const char *path, int follow_leaf)
{
    struct stat st;
    int fd = -1;
    FILE *fp;
    int saved;

    if (walk_monitored(path, follow_leaf, &st, &fd) < 0) {
        return (NULL);
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        saved = errno;
        close(fd);
        errno = saved;
    }
    return (fp);
}

#else /* WIN32 */

int fim_lstat_entry(DIR *parent, const char *name, const char *path,
                    struct stat *st)
{
    (void)parent;
    (void)name;
    return (stat(path, st));
}

int fim_open_entry(DIR *parent, const char *name, const char *path, int flags)
{
    (void)parent;
    (void)name;
    return (open(path, flags));
}

int fim_open_entry_follow(DIR *parent, const char *name, const char *path)
{
    (void)parent;
    (void)name;
    return (open(path, O_RDONLY));
}

DIR *fim_opendir_entry(DIR *parent, const char *name, const char *path)
{
    (void)parent;
    (void)name;
    return (opendir(path));
}

int fim_lstat_monitored(const char *path, struct stat *st)
{
    return (stat(path, st));
}

FILE *fim_fopen_monitored(const char *path, int follow_leaf)
{
    (void)follow_leaf;
    return (fopen(path, "rb"));
}

#endif /* WIN32 */
