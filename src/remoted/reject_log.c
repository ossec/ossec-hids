/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "remoted.h"

/* Anyone who can reach a listener can have input rejected, so logging every
 * rejection lets them flood ossec.log. Allow a small burst per interval so
 * distinct rejected hosts remain visible, then count the rest and report the
 * skipped total when the window rolls (ANT-2026-JA2NXEW1).
 */
int remoted_log_reject(void)
{
    time_t now;

    if (!remoted_self) {
        return (1);
    }

    now = time(NULL);

    /* Backward clock jumps restart the window so logging is not suppressed
     * until wall time catches up to a previous reject_last.
     */
    if (remoted_self->reject_last == 0 ||
        now < remoted_self->reject_last ||
        now - remoted_self->reject_last >= REMOTED_REJECT_LOG_INTERVAL) {
        if (remoted_self->reject_count > REMOTED_REJECT_LOG_BURST) {
            merror("%s: WARN: %u more rejected messages were not logged "
                   "(limit %d every %d seconds).",
                   ARGV0,
                   remoted_self->reject_count - REMOTED_REJECT_LOG_BURST,
                   REMOTED_REJECT_LOG_BURST,
                   REMOTED_REJECT_LOG_INTERVAL);
        }
        remoted_self->reject_last = now;
        remoted_self->reject_count = 0;
    }

    remoted_self->reject_count++;
    if (remoted_self->reject_count <= REMOTED_REJECT_LOG_BURST) {
        return (1);
    }
    return (0);
}
