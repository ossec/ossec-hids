/*
 * ANT-2026-D7ZVXNZP: <syscheck><prefilter_cmd> from the manager-pushed
 * agent.conf must be refused unless remote commands are opted in — the
 * same gate <localfile><command> already has via logcollector.remote_commands.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_prefilter_remote_cmd
 */

#include <stdio.h>

#include "config/syscheck_remote_cmd.h"

int main(void)
{
    int failed = 0;

    printf("=== ANT-2026-D7ZVXNZP: prefilter_cmd remote gate ===\n");

    /* Local ossec.conf parse: agent_cfg == 0 → always allowed. */
    if (!OS_SyscheckRemotePrefilterAllowed(0, 0)) {
        printf("  FAIL: local config refused with accept_remote=0\n");
        failed = 1;
    } else {
        printf("  ok: local ossec.conf allowed\n");
    }

    /* Shared agent.conf with remote_commands=0 → must refuse. */
    if (OS_SyscheckRemotePrefilterAllowed(1, 0)) {
        printf("  FAIL: agent.conf allowed with accept_remote=0\n");
        failed = 1;
    } else {
        printf("  ok: agent.conf refused when remote_commands=0\n");
    }

    /* Shared agent.conf with remote_commands=1 → allowed. */
    if (!OS_SyscheckRemotePrefilterAllowed(1, 1)) {
        printf("  FAIL: agent.conf refused with accept_remote=1\n");
        failed = 1;
    } else {
        printf("  ok: agent.conf allowed when remote_commands=1\n");
    }

    if (failed) {
        printf("\nFAIL: issue_prefilter_remote_cmd\n");
        return 1;
    }

    printf("\nPASS: issue_prefilter_remote_cmd\n");
    return 0;
}
