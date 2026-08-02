/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Location-hash shards isolate Search_LastEvents / EventList history per
 * agent location (or hostname). Cross-agent frequency/context must use
 * if_matched_sid / if_matched_group (global sid lists under rule->mutex).
 * Stock brute-force rules that use if_matched_sid remain correct; pure
 * context+frequency rules only correlate within a single location shard.
 *
 * Migration checklist (rule_matching_threads > 1):
 * 1. Inventory frequency/context rules that expect events from multiple agents.
 * 2. Prefer if_matched_sid / if_matched_group for those patterns.
 * 3. Keep pure Search_LastEvents rules when correlation is intentionally local.
 * 4. Cover cross-agent sid lists with regressions (issue_correlation_agent_shard).
 */

#ifndef WIN32

#include "shared.h"
#include "correlation_shard.h"
#include "eventinfo.h"

unsigned int analysisd_shard_id(const Eventinfo *lf, unsigned int nshards)
{
    const char *key;
    unsigned int h = 5381;
    unsigned char c;

    if (nshards <= 1) {
        return 0;
    }

    key = lf && lf->location ? lf->location : (lf && lf->hostname ? lf->hostname : "");
    while ((c = (unsigned char)*key++) != '\0') {
        h = ((h << 5) + h) + c;
    }

    return h % nshards;
}

#endif /* !WIN32 */
