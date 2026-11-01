/*
 * ANT-2026-PWED0R2H: demux must not soak on syscheck/rootcheck/hostinfo decode
 * queues, and decode workers must not soak on a full rule-matching shard when
 * more than one shard exists — otherwise one agent stalls every other agent.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_pwed0r2h_demux_push_wait
 */

#include <stdio.h>

#include "pipeline_push_wait.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

int main(void)
{
    const int demux_cfg = 50;
    const int shard_cfg = 75;

    printf("ANT-2026-PWED0R2H demux/shard push-wait isolation\n");

    CHECK(analysisd_demux_typed_wait_ms(SYSCHECK_MQ, demux_cfg) == 0,
          "syscheck demux push does not soak");
    CHECK(analysisd_demux_typed_wait_ms(ROOTCHECK_MQ, demux_cfg) == 0,
          "rootcheck demux push does not soak");
    CHECK(analysisd_demux_typed_wait_ms(HOSTINFO_MQ, demux_cfg) == 0,
          "hostinfo demux push does not soak");
    CHECK(analysisd_demux_typed_wait_ms('1', demux_cfg) == demux_cfg,
          "log-event demux push keeps configured soak");
    CHECK(analysisd_demux_typed_wait_ms('5', demux_cfg) == demux_cfg,
          "other log-type demux push keeps configured soak");

    CHECK(analysisd_shard_typed_wait_ms(1, shard_cfg) == shard_cfg,
          "single shard may soak with configured wait");
    CHECK(analysisd_shard_typed_wait_ms(2, shard_cfg) == 0,
          "multi-shard decode push does not soak");
    CHECK(analysisd_shard_typed_wait_ms(8, shard_cfg) == 0,
          "many shards still shed a full shard immediately");

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
