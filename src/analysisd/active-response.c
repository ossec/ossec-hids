/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "active-response.h"

#ifndef WIN32
#include <sys/types.h>
#include <grp.h>
#include <unistd.h>
#endif

/* Active response commands */
static OSList *ar_commands;
OSList *active_responses;

static OSList *ar_staging_commands;
static OSList *ar_staging_responses;
static int ar_staging_saved_flag = 0;
static int ar_staging_flag_saved = 0;

static void Free_ARCommand(void *data);
static void Free_AR(void *data);

static int ar_serialize_responses_to_fp(FILE *fp, OSList *responses)
{
    OSListNode *node;
    int skipped = 0;

    if (!fp || !responses) {
        return (OS_INVALID);
    }

    node = OSList_GetFirstNode(responses);
    while (node) {
        active_response *ar = (active_response *)node->data;

        if (ar && ar->name && ar->ar_cmd && ar->ar_cmd->executable) {
            fprintf(fp, "%s - %s - %d\n",
                    ar->name,
                    ar->ar_cmd->executable,
                    ar->timeout);
        } else if (ar) {
            skipped++;
        }
        node = OSList_GetNextNode(responses);
    }

    if (skipped > 0) {
        merror("%s: WARNING: Skipped %d active-response entries missing name or command.",
               ARGV0, skipped);
    }

    return (0);
}

static int ar_apply_arconf_permissions(const char *arpath)
{
#ifndef WIN32
    struct group *os_group;

    if ((os_group = getgrnam(USER)) != NULL) {
        if (chown(arpath, (uid_t) - 1, os_group->gr_gid) == -1) {
            merror("%s: WARNING: Could not chown '%s': %d", ARGV0, arpath, errno);
        }
    }
#endif
    if (chmod(arpath, 0440) == -1) {
        merror(CHMOD_ERROR, ARGV0, arpath, errno, strerror(errno));
        return (OS_INVALID);
    }

    return (0);
}

static int ar_write_config_file(OSList *responses)
{
    FILE *fp;
    const char *arpath;
    char tmppath[OS_FLSIZE + 16];
    int ar_rewrite = 1;

    /* Before chroot use absolute DEFAULTDIR path; after chroot use etc/shared. */
    arpath = (geteuid() != 0 || isChroot()) ? DEFAULTAR : DEFAULTARPATH;

    if (geteuid() != 0) {
        merror("%s: INFO: Cannot rewrite '%s' on reload (not root). "
                 "Using existing file.", ARGV0, arpath);
        fp = fopen("var/run/ar_reload_sink", "w");
        ar_rewrite = 0;
        if (!fp) {
            merror(FOPEN_ERROR, ARGV0, "var/run/ar_reload_sink", errno, strerror(errno));
            return (OS_INVALID);
        }
    } else {
        snprintf(tmppath, sizeof(tmppath), "%s.reload.tmp", arpath);
        fp = fopen(tmppath, "w");
        if (!fp) {
            merror(FOPEN_ERROR, ARGV0, tmppath, errno, strerror(errno));
            return (OS_INVALID);
        }
    }

    fprintf(fp, "restart-ossec0 - restart-ossec.sh - 0\n");
    fprintf(fp, "restart-ossec0 - restart-ossec.cmd - 0\n");

    if (ar_serialize_responses_to_fp(fp, responses) < 0) {
        fclose(fp);
        if (ar_rewrite) {
            unlink(tmppath);
        }
        return (OS_INVALID);
    }

    fflush(fp);
#ifndef WIN32
    if (ar_rewrite) {
        fsync(fileno(fp));
    }
#endif
    fclose(fp);

    if (!ar_rewrite) {
        return (0);
    }

    if (ar_apply_arconf_permissions(tmppath) < 0) {
        unlink(tmppath);
        return (OS_INVALID);
    }

    if (rename(tmppath, arpath) < 0) {
        merror("%s: ERROR: Could not install '%s' from '%s': (%d) %s",
               ARGV0, arpath, tmppath, errno, strerror(errno));
        unlink(tmppath);
        return (OS_INVALID);
    }

    return (0);
}

void AR_AbortConfigStaging(void)
{
    if (ar_staging_commands) {
        OSList_SetFreeDataPointer(ar_staging_commands, Free_ARCommand);
        OSList_Free(ar_staging_commands);
        ar_staging_commands = NULL;
    }
    if (ar_staging_responses) {
        OSList_SetFreeDataPointer(ar_staging_responses, Free_AR);
        OSList_Free(ar_staging_responses);
        ar_staging_responses = NULL;
    }

    if (ar_staging_flag_saved) {
        ar_flag = ar_staging_saved_flag;
        ar_staging_flag_saved = 0;
    }
}

int AR_LoadConfigStaging(const char *cfgfile)
{
    int modules = CAR;
    int rc;

    AR_AbortConfigStaging();

    ar_staging_commands = OSList_Create();
    ar_staging_responses = OSList_Create();
    if (!ar_staging_commands || !ar_staging_responses) {
        AR_AbortConfigStaging();
        return (OS_INVALID);
    }

    ar_staging_saved_flag = ar_flag;
    ar_staging_flag_saved = 1;
    ar_flag = 0;

    AR_SetSkipSharedFileWrite(1);
    rc = ReadConfig(modules, cfgfile, ar_staging_commands, ar_staging_responses);
    AR_SetSkipSharedFileWrite(0);

    if (rc < 0) {
        AR_AbortConfigStaging();
        return (OS_INVALID);
    }

    return (0);
}

int AR_CommitConfig(void)
{
    if (!ar_staging_commands || !ar_staging_responses) {
        return (OS_INVALID);
    }

    if (ar_write_config_file(ar_staging_responses) < 0) {
        return (OS_INVALID);
    }

    if (geteuid() != 0 || isChroot()) {
        merror("%s: INFO: Active response updated in memory only; restart ossec-execd "
               "if command definitions changed.", ARGV0);
    }

    ar_staging_flag_saved = 0;

    FreeARConfig();
    ar_commands = ar_staging_commands;
    active_responses = ar_staging_responses;
    ar_staging_commands = NULL;
    ar_staging_responses = NULL;

    return (0);
}

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
int AR_ReadConfig(const char *cfgfile)
{
    if (AR_LoadConfigStaging(cfgfile) < 0) {
        return (OS_INVALID);
    }

    if (AR_CommitConfig() < 0) {
        AR_AbortConfigStaging();
        return (OS_INVALID);
    }

    return (0);
}


/* Free an ar_command structure */
static void Free_ARCommand(void *data)
{
    ar_command *cmd = (ar_command *)data;
    if (cmd) {
        free(cmd->name);
        free(cmd->executable);
        free(cmd);
    }
}

/* Free an active_response structure */
static void Free_AR(void *data)
{
    active_response *ar = (active_response *)data;
    if (ar) {
        free(ar->name);
        free(ar->command);
        free(ar->agent_id);
        free(ar->rules_id);
        free(ar->rules_group);
        /* ar_cmd is a pointer to an element in ar_commands, so we don't free it here */
        free(ar);
    }
}

/* Free the active response configuration */
void FreeARConfig()
{
    if (ar_commands) {
        OSList_SetFreeDataPointer(ar_commands, Free_ARCommand);
        OSList_Free(ar_commands);
        ar_commands = NULL;
    }
    if (active_responses) {
        OSList_SetFreeDataPointer(active_responses, Free_AR);
        OSList_Free(active_responses);
        active_responses = NULL;
    }
}
