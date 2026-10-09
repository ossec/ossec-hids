/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "setup-shared.h"

/*
 * Replace inherited ACEs with an allow-list: NT AUTHORITY\SYSTEM (the
 * OssecSvc account) and BUILTIN\Administrators. (OI)(CI) propagates to
 * files and subfolders (#182).
 */
static int set_allow_list(void)
{
    const char *cmds[] = {
        /* /reset drops explicit grants left by an older install.
         * /inheritance:r then removes the inherited ACEs /reset restored,
         * and the two grants are the only remaining access.
         */
        "icacls . /reset /T /C /Q",
        "icacls . /inheritance:r /T /C /Q",
        "icacls . /grant \"*S-1-5-18:(OI)(CI)F\" /T /C /Q",
        "icacls . /grant \"*S-1-5-32-544:(OI)(CI)F\" /T /C /Q",
        NULL
    };
    int i;

    for (i = 0; cmds[i] != NULL; i++) {
        int rc = system(cmds[i]);

        if (rc != 0) {
            printf("%s: ERROR: '%s' returned %d.\n", ARGV0, cmds[i], rc);
            return (0);
        }
    }

    return (1);
}

/* Set up Windows after installation */
int main(int argc, char **argv)
{
    /* Set the name */
    OS_SetName(ARGV0);

    if (argc < 2) {
        printf("%s: Invalid syntax.\n", argv[0]);
        printf("Try: '%s directory'\n\n", argv[0]);
        return (0);
    }

    /* Try to chdir to the OSSEC directory */
    if (chdir(argv[1]) != 0) {
        printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
        return (0);
    }

    /* Configure OSSEC for automatic startup */
    system("sc config OssecSvc start= auto");

    /* Change permissions */
    checkVista();

    if (isVista) {
        char cmd[OS_MAXSTR + 1];

        /* Copy some files to outside */
        snprintf(cmd, OS_MAXSTR, "move os_win32ui.exe ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move win32ui.exe ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move uninstall.exe ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move doc.html ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move help.txt ../");
        system(cmd);

        /* Allow SYSTEM and Administrators; UI and docs are moved aside. */
        {
            int acl_ok = set_allow_list();

            /* Copy them back */
            snprintf(cmd, OS_MAXSTR, "move ..\\os_win32ui.exe .");
            system(cmd);

            snprintf(cmd, OS_MAXSTR, "move ..\\win32ui.exe .");
            system(cmd);

            snprintf(cmd, OS_MAXSTR, "move ..\\uninstall.exe .");
            system(cmd);

            snprintf(cmd, OS_MAXSTR, "move ..\\doc.html .");
            system(cmd);

            snprintf(cmd, OS_MAXSTR, "move ..\\help.txt .");
            system(cmd);

            if (!acl_ok) {
                return (0);
            }
        }
    } else {
        if (!set_allow_list()) {
            return (0);
        }
    }

    return (1);
}
