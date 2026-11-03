/*
 * ANT-2026-JA2NXEW1: remoted must rate-limit pre-auth rejection logging.
 *
 * Without a burst-aware gate, each refused datagram appends one ossec.log
 * line and an unauthenticated sender can fill logs/. remoted_log_reject()
 * allows REMOTED_REJECT_LOG_BURST lines per REMOTED_REJECT_LOG_INTERVAL,
 * then only counts further rejections until the window rolls.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_ja2nxew1_reject_log
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "remoted/remoted.h"

const char *__local_name = "issue-ja2nxew1-reject-log";

/* remoted_log_reject() reads remoted_self (thread-local in remoted). */
__thread remoted_listener *remoted_self = NULL;

/* Unused remoted globals the header declares — satisfy the linker. */
keystore keys;
remoted logr;
remoted_listener remoted_listeners[REMOTE_LISTENERS_MAX];
remoted_listener *remoted_secure_listener = NULL;
volatile sig_atomic_t remoted_shutting_down = 0;
volatile sig_atomic_t remoted_force_exit = 0;

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void test_burst_then_suppress(void)
{
    remoted_listener listener;
    int i;
    int allowed = 0;
    int denied = 0;

    memset(&listener, 0, sizeof(listener));
    remoted_self = &listener;

    for (i = 0; i < REMOTED_REJECT_LOG_BURST + 10; i++) {
        if (remoted_log_reject()) {
            allowed++;
        } else {
            denied++;
        }
    }

    CHECK(allowed == REMOTED_REJECT_LOG_BURST,
          "first REMOTED_REJECT_LOG_BURST rejections may log");
    CHECK(denied == 10,
          "further rejections in the same window are only counted");
    CHECK(listener.reject_count == (unsigned)(REMOTED_REJECT_LOG_BURST + 10),
          "reject_count tracks every attempt in the window");

    remoted_self = NULL;
}

int main(void)
{
    printf("issue_ja2nxew1_reject_log:\n");
    test_burst_then_suppress();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return (1);
    }
    printf("OK\n");
    return (0);
}
