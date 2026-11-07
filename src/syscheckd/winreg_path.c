/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>

#include "winreg_path.h"

int os_winreg_build_subkey_paths(char *new_key, char *new_key_full,
                                 size_t max_key, const char *p_key,
                                 const char *full_key_name,
                                 const char *sub_key_name)
{
    int len;
    int len_full;

    if (!new_key || !new_key_full || !full_key_name || !sub_key_name ||
            max_key == 0) {
        return (-1);
    }

    if (p_key) {
        len = snprintf(new_key, max_key, "%s\\%s", p_key, sub_key_name);
    } else {
        len = snprintf(new_key, max_key, "%s", sub_key_name);
    }
    len_full = snprintf(new_key_full, max_key, "%s\\%s",
                        full_key_name, sub_key_name);

    /* A truncated path names a different key — possibly this very one,
     * which would then be walked again and again. ANT-2026-SI19UF16.
     */
    if (len < 0 || (size_t)len >= max_key ||
            len_full < 0 || (size_t)len_full >= max_key) {
        return (-1);
    }

    return (0);
}
