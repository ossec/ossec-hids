/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Path join helpers for syscheck directory walks (ANT-2026-1UF4D24F).
 */

#include "shared.h"
#include "syscheck.h"

int OS_SyscheckEntryFits(size_t dir_size, size_t name_len, int needs_sep)
{
    /* Room for optional '/', entry name, and NUL. Rejects the old
     * PATH_MAX - dir_size - 2 wrap when dir_size is near PATH_MAX. */
    size_t need = dir_size + name_len + 1; /* name + NUL */

    if (needs_sep) {
        need++;
    }
    return (need <= (size_t)PATH_MAX);
}

int OS_SyscheckJoinEntryPath(char *f_name, size_t f_name_sz,
                             const char *dir_name, size_t dir_size,
                             const char *entry_name)
{
    char *s_name;
    size_t remain;
    size_t name_len;
    int needs_sep;

    if (!f_name || !dir_name || !entry_name || f_name_sz < 3) {
        return (-1);
    }

    name_len = strlen(entry_name);
    needs_sep = (dir_size > 0 && dir_name[dir_size - 1] != '/');
    if (!OS_SyscheckEntryFits(dir_size, name_len, needs_sep)) {
        return (-1);
    }

    if (dir_size >= f_name_sz) {
        return (-1);
    }

    memcpy(f_name, dir_name, dir_size);
    s_name = f_name + dir_size;

    if (needs_sep) {
        if ((size_t)(s_name - f_name) + 1 >= f_name_sz) {
            return (-1);
        }
        *s_name++ = '/';
    }
    *s_name = '\0';

    remain = f_name_sz - (size_t)(s_name - f_name);
    if (remain == 0) {
        return (-1);
    }

    /* snprintf with remaining room — never PATH_MAX - dir_size - 2. */
    if ((size_t)snprintf(s_name, remain, "%s", entry_name) >= remain) {
        return (-1);
    }
    return (0);
}
