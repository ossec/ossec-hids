/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"

/* Cap how many times the PID scan may sleep in one pass so a local
 * user cannot stretch the pause indefinitely (ANT-2026-AE2I21JQ).
 */
int rk_pid_budget_take(int *paused, int limit)
{
    if (paused == NULL || limit <= 0) {
        return (0);
    }
    if (*paused >= limit) {
        return (0);
    }
    (*paused)++;
    return (1);
}
