/*
 * ANT-2026-AE2I21JQ: rootcheck PID-scan pauses must be budgeted so idle
 * threads / many live PIDs cannot stall realtime FIM for hours.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ae2i21jq_pid_sleep
 */

#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "rootcheck.h"

int main(void)
{
    int paused = 0;
    int i;
    int failed = 0;

    printf("=== ANT-2026-AE2I21JQ: PID-scan sleep budget ===\n");

    for (i = 0; i < 32; i++) {
        if (!rk_pid_budget_take(&paused, 32)) {
            printf("  FAIL: budget exhausted early at %d\n", i);
            failed = 1;
            break;
        }
    }
    if (!failed && paused != 32) {
        printf("  FAIL: paused=%d want 32\n", paused);
        failed = 1;
    } else if (!failed) {
        printf("  ok: 32 pauses allowed when sleep_after=32\n");
    }

    if (rk_pid_budget_take(&paused, 32)) {
        printf("  FAIL: 33rd pause should be refused\n");
        failed = 1;
    } else {
        printf("  ok: further pauses refused once budget is spent\n");
    }

    paused = 0;
    if (rk_pid_budget_take(&paused, 1) != 1 ||
            rk_pid_budget_take(&paused, 1) != 0) {
        printf("  FAIL: sleep_after=1 should allow exactly one pause\n");
        failed = 1;
    } else {
        printf("  ok: sleep_after=1 allows exactly one pause\n");
    }

    paused = 0;
    if (rk_pid_budget_take(&paused, 0) || rk_pid_budget_take(NULL, 32)) {
        printf("  FAIL: limit<=0 / NULL should refuse\n");
        failed = 1;
    } else {
        printf("  ok: invalid budget args refused\n");
    }

    if (failed) {
        printf("\nFAIL: issue_ae2i21jq_pid_sleep\n");
        return (1);
    }
    printf("\nPASS: issue_ae2i21jq_pid_sleep\n");
    return (0);
}
