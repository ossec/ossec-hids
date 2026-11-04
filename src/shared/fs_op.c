/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to retrieve information about the filesystem
 */


#include "shared.h"
#ifndef ARGV0
#define ARGV0 "fs_op"
#endif

const struct file_system_type network_file_systems[] = {
    {.name="NFS",  .f_type=0x6969,     .flag=1},
    {.name="CIFS", .f_type=0xFF534D42, .flag=1},

    /*  The last entry must be name=NULL */
    {.name=NULL, .f_type=0, .flag=0}
};

/* List of filesystem to skip the link count test */
const struct file_system_type skip_file_systems[] = {
    {.name="BTRFS", .f_type=0x9123683E, .flag=1},
    {.name="AUFS", .f_type=0x61756673, .flag=1},
    {.name="OVERLAYFS", .f_type=0x794c7630, .flag=1},

    /*  The last entry must be name=NULL */
    {.name=NULL, .f_type=0, .flag=0}
};

static short match_fs_type(const struct file_system_type *table,
                           const struct statfs *stfs)
{
    int i;

    for (i = 0; table[i].name != NULL; i++) {
#if defined(__OpenBSD__)
        if (strcasecmp(table[i].name, stfs->f_fstypename) == 0) {
#else
        if (table[i].f_type == stfs->f_type) {
#endif
            return (short)table[i].flag;
        }
    }
    return (0);
}

short IsNFS_fd(int fd)
{
#if !defined(WIN32) && (defined(Linux) || defined(FreeBSD) || defined(OpenBSD))
    struct statfs stfs;

    if (fstatfs(fd, &stfs) == 0) {
        return (match_fs_type(network_file_systems, &stfs));
    }
    return (-1);
#else
    (void)fd;
    return (0);
#endif
}

short skipFS_fd(int fd)
{
#if !defined(WIN32) && (defined(Linux) || defined(FreeBSD) || defined(OpenBSD))
    struct statfs stfs;
    short flag;

    if (fstatfs(fd, &stfs) == 0) {
        flag = match_fs_type(skip_file_systems, &stfs);
        if (flag) {
            debug1("%s: Skipping dir (FS match on fd %d)", ARGV0, fd);
        }
        return (flag);
    }
    /* Unknown FS: keep prior skip so link-count does not false-alert. */
    return (-1);
#else
    (void)fd;
    return (0);
#endif
}

short IsNFS(const char *dir_name)
{
#if !defined(WIN32) && (defined(Linux) || defined(FreeBSD) || defined(OpenBSD))
    struct statfs stfs;

    /* ignore NFS (0x6969) or CIFS (0xFF534D42) mounts */
    if ( ! statfs(dir_name, &stfs) )
    {
        return (match_fs_type(network_file_systems, &stfs));
    }
    else
    {
        /* If the file exists, throw an error and retreat! If the file does not exist, there
	 * is no reason to spam the log with these errors. */
	if(errno != ENOENT) {
            merror("ERROR: statfs('%s') produced error: %s", dir_name, strerror(errno));
	}
        return(-1);
    }
#else
    verbose(
        "INFO: Attempted to check NFS status for '%s', but we don't know how on this OS.",
        dir_name
    );
#endif
    return(0);
}

short skipFS(const char *dir_name)
{
#if !defined(WIN32) && (defined(Linux) || defined(FreeBSD) || defined(OpenBSD))
    struct statfs stfs;

    if ( ! statfs(dir_name, &stfs) )
    {
        int i;
        for ( i=0; skip_file_systems[i].name != NULL; i++ ) {
#if defined(__OpenBSD__)
            if(strcasecmp(skip_file_systems[i].name, stfs.f_fstypename) == 0) {
#else
            if(skip_file_systems[i].f_type == stfs.f_type ) {
#endif
                debug1("%s: Skipping dir (FS %s): %s ", ARGV0, skip_file_systems[i].name, dir_name);
                return skip_file_systems[i].flag;
            }
        }
        return(0);
    }
    else
    {
        /* If the file exists, throw an error and retreat! If the file does not exist, there
         * is no reason to spam the log with these errors. */
        if(errno != ENOENT) {
            merror("ERROR: statfs('%s') produced error: %s", dir_name, strerror(errno));
        }
        return(-1);
    }
#else
#ifndef WIN32
    debug2(
        "INFO: Attempted to check FS status for '%s', but we don't know how on this OS.",
        dir_name
    );
#endif
#endif
    return(0);
}


/* EOF */
