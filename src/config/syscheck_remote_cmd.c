/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Gate for <syscheck><prefilter_cmd> from agent.conf (ANT-2026-D7ZVXNZP).
 */

#include "syscheck_remote_cmd.h"

int OS_SyscheckRemotePrefilterAllowed(int agent_cfg, int accept_remote)
{
    /* Same invariant as <localfile><command>: shared agent.conf may not
     * supply a command unless the agent opted in. */
    if (agent_cfg == 1 && accept_remote == 0) {
        return (0);
    }
    return (1);
}
