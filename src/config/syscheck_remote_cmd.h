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

#ifndef SYSCHECK_REMOTE_CMD_H
#define SYSCHECK_REMOTE_CMD_H

/* 1 if a prefilter_cmd from this parse pass may be applied.
 * agent_cfg: set while reading the shared agent.conf
 * accept_remote: logcollector.remote_commands (same opt-in as <command>) */
int OS_SyscheckRemotePrefilterAllowed(int agent_cfg, int accept_remote);

#endif /* SYSCHECK_REMOTE_CMD_H */
