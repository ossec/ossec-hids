/* Copyright (C) 2026 Atomicorp
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <string.h>

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
     * \\?\C:\ is a local extended path unless that drive is mapped.
     */
    if (os_path_sep(p[0]) && os_path_sep(p[1])) {
        if (!(p[2] == '?' && os_path_sep(p[3]) &&
              os_drive_letter(p[4]) && p[5] == ':')) {
            return (1);
        }
#ifndef WIN32
        return (0);
#else
        p += 4;
#endif
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

/* Case-insensitive match of a single path component at p. */
static int os_win_component_eq(const char *p, const char *name, size_t nlen)
{
    size_t i;

    for (i = 0; i < nlen; i++) {
        char a = p[i];
        char b = name[i];

        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return (0);
        }
    }
    return (p[nlen] == '\0' || os_path_sep(p[nlen]));
}

/* Pointer to the named component, or NULL. */
static const char *os_win_find_component(const char *path, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = path;

    if (path == NULL || name == NULL || name[0] == '\0') {
        return (NULL);
    }

    if (os_win_component_eq(p, name, nlen)) {
        return (p);
    }
    while (*p != '\0') {
        if (os_path_sep(*p) && os_win_component_eq(p + 1, name, nlen)) {
            return (p + 1);
        }
        p++;
    }
    return (NULL);
}

int os_win_sysnative_rewrite(const char *in, char *out, size_t n)
{
    const char *hit;
    size_t prefix;
    size_t need;
    const char *rest;
    static const char sysnative[] = "Sysnative";

    if (in == NULL || out == NULL || n == 0) {
        return (0);
    }
    out[0] = '\0';

    /* Explicit 32-bit or already-native views stay as configured. */
    if (os_win_find_component(in, "Sysnative") != NULL ||
            os_win_find_component(in, "SysWOW64") != NULL) {
        return (0);
    }

    hit = os_win_find_component(in, "System32");
    if (hit == NULL) {
        return (0);
    }

    prefix = (size_t)(hit - in);
    rest = hit + strlen("System32");
    need = prefix + strlen(sysnative) + strlen(rest) + 1;
    if (need > n) {
        return (0);
    }

    memcpy(out, in, prefix);
    memcpy(out + prefix, sysnative, strlen(sysnative));
    memcpy(out + prefix + strlen(sysnative), rest, strlen(rest) + 1);
    return (1);
}

#ifdef WIN32
int os_win_is_wow64(void)
{
#ifdef _WIN64
    return (0);
#else
    {
        static int cached = -1;
        BOOL wow64 = FALSE;
        typedef BOOL (WINAPI *fn_IsWow64Process)(HANDLE, PBOOL);
        fn_IsWow64Process fn;
        FARPROC proc;

        if (cached != -1) {
            return (cached);
        }

        proc = GetProcAddress(GetModuleHandle("kernel32.dll"),
                              "IsWow64Process");
        fn = (fn_IsWow64Process)(void *)proc;
        if (fn && fn(GetCurrentProcess(), &wow64) && wow64) {
            cached = 1;
        } else {
            cached = 0;
        }
        return (cached);
    }
#endif
}
#endif /* WIN32 */
