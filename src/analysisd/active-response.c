/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "shared.h"
#include "active-response.h"

/* Active response commands */
static OSList *ar_commands;
OSList *active_responses;

/* Initialize active response */
void AR_Init()
{
    ar_commands = OSList_Create();
    active_responses = OSList_Create();
    ar_flag = 0;

    if (!ar_commands || !active_responses) {
        ErrorExit(LIST_ERROR, ARGV0);
    }
}

/* Read active response configuration and write it
 * to the appropriate lists.
 */
int AR_ReadConfig(const char *cfgfile, gid_t gid)
{
    FILE *fp;
    int fd;
    int modules = 0;
    OSListNode *node;

    modules |= CAR;

    /* Read configuration first so every <active-response> block is on the
     * list before we touch the shared file. */
    if (ReadConfig(modules, cfgfile, ar_commands, active_responses) < 0) {
        return (OS_INVALID);
    }

    /* Write the shared ar file. We still run as root and etc/shared is
     * writable by the ossec group, so never open, chown or chmod whatever
     * is currently at that name: replace it with a new file (O_EXCL also
     * refuses a symlink planted there) and work on its descriptor only.
     */
    if (unlink(DEFAULTARPATH) == -1 && errno != ENOENT) {
        merror(DELETE_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return (OS_INVALID);
    }

    fd = open(DEFAULTARPATH, O_WRONLY | O_CREAT | O_EXCL, 0440);
    if (fd == -1) {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return (OS_INVALID);
    }

    if (fchown(fd, (uid_t) - 1, gid) == -1) {
        merror(CHOWN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        close(fd);
        unlink(DEFAULTARPATH);
        return (OS_INVALID);
    }
    if (fchmod(fd, 0440) == -1) {
        merror(CHMOD_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        close(fd);
        unlink(DEFAULTARPATH);
        return (OS_INVALID);
    }

    fp = fdopen(fd, "w");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        close(fd);
        unlink(DEFAULTARPATH);
        return (OS_INVALID);
    }

    fprintf(fp, "restart-ossec0 - restart-ossec.sh - 0\n");
    fprintf(fp, "restart-ossec0 - restart-ossec.cmd - 0\n");

    node = OSList_GetFirstNode(active_responses);
    while (node) {
        active_response *ar = (active_response *) node->data;

        debug1("writing command '%s' to '%s'", ar->command, DEFAULTARPATH);
        fprintf(fp, "%s - %s - %d\n",
                ar->name,
                ar->ar_cmd->executable,
                ar->timeout);

        node = OSList_GetNextNode(active_responses);
    }

    if (fclose(fp) != 0) {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        unlink(DEFAULTARPATH);
        return (OS_INVALID);
    }

    return (0);
}
