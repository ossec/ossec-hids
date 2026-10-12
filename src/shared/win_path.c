/* Copyright (C) 2026 Atomicorp
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "file_op.h"

#ifdef WIN32
#include <windows.h>
#endif

static int os_path_sep(char c)
{
    return (c == '\\' || c == '/');
}

static int os_drive_letter(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

int os_win_network_path(const char *path)
{
    const char *p;

    if (path == NULL) {
        return (0);
    }

    p = path;
    while (*p == ' ') {
        p++;
    }

    /* \\server\share, \\?\UNC\..., \\.\pipe\..., and the // forms.
     * \\?\C:\ is the local extended-length prefix.
     */
    if (os_path_sep(p[0]) && os_path_sep(p[1])) {
        if (p[2] == '?' && os_path_sep(p[3]) && os_drive_letter(p[4]) && p[5] == ':') {
            return (0);
        }
        return (1);
    }

#ifdef WIN32
    if (os_drive_letter(p[0]) && p[1] == ':') {
        char root[4];

        root[0] = p[0];
        root[1] = ':';
        root[2] = '\\';
        root[3] = '\0';
        if (GetDriveType(root) == DRIVE_REMOTE) {
            return (1);
        }
    }
#endif

    return (0);
}
