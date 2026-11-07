/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WINREG_PATH_H
#define WINREG_PATH_H

#include <stddef.h>

/* Match syscheckd/win-registry.c MAX_KEY. */
#define OS_WINREG_MAX_KEY 2048

/* Build the open path and full name for a registry subkey into buffers of
 * size max_key (snprintf-style: at most max_key-1 payload bytes). Returns 0
 * when both fit, or -1 when either would be truncated (so the caller must
 * not open the result — a truncated path can name the parent again).
 * ANT-2026-SI19UF16.
 */
int os_winreg_build_subkey_paths(char *new_key, char *new_key_full,
                                 size_t max_key, const char *p_key,
                                 const char *full_key_name,
                                 const char *sub_key_name);

#endif
