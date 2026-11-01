/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * Demux / shard mid-pipe soak policy (ANT-2026-PWED0R2H).
 * Shared by pipeline.c and its regression so the wait policy is unit-tested
 * without linking the full analysisd pipeline.
 */

#ifndef ANALYSISD_PIPELINE_PUSH_WAIT_H
#define ANALYSISD_PIPELINE_PUSH_WAIT_H

#include "headers/mq_op.h"

/*
 * Demux workers serve every message type. Soak only the log-event queue;
 * syscheck/rootcheck/hostinfo have agent-sized DBs, so a full queue for those
 * types must shed immediately instead of parking demux for all agents
 * (ANT-2026-PWED0R2H).
 */
static inline int analysisd_demux_typed_wait_ms(char mq_prefix, int demux_cfg_ms)
{
    switch (mq_prefix) {
        case SYSCHECK_MQ:
        case ROOTCHECK_MQ:
        case HOSTINFO_MQ:
            return 0;
        default:
            return demux_cfg_ms;
    }
}

/*
 * Decode workers serve every rule-matching shard. With more than one shard the
 * sender picks the shard via location, so a full shard must drop without
 * parking the shared decode pool (ANT-2026-PWED0R2H).
 */
static inline int analysisd_shard_typed_wait_ms(int thread_count, int shard_cfg_ms)
{
    if (thread_count <= 1) {
        return shard_cfg_ms;
    }
    return 0;
}

#endif /* ANALYSISD_PIPELINE_PUSH_WAIT_H */
