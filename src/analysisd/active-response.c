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
int AR_ReadConfig(const char *cfgfile)
{
    FILE *fp;
    int modules = 0;

    modules |= CAR;

    /* Clean ar file */
    fp = fopen(DEFAULTARPATH, "w");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return (OS_INVALID);
    }
    fprintf(fp, "restart-ossec0 - restart-ossec.sh - 0\n");
    fprintf(fp, "restart-ossec0 - restart-ossec.cmd - 0\n");
    fclose(fp);

    /* Set right permission */
    if (chmod(DEFAULTARPATH, 0440) == -1) {
        merror(CHMOD_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return (OS_INVALID);
    }

    /* Read configuration */
    if (ReadConfig(modules, cfgfile, ar_commands, active_responses) < 0) {
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
        OSList_CleanNodes(ar_commands);
    }
    if (active_responses) {
        OSList_SetFreeDataPointer(active_responses, Free_AR);
        OSList_CleanNodes(active_responses);
    }
}
