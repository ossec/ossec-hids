/*
 * Regression for ANT-2026-9LQQ1BMS: classic OSRegex/OSMatch must match
 * subjects byte-wise. With PCRE2_UTF, a Latin-1 byte in an otherwise
 * matching line is treated as no match, and an invalid-UTF-8 pattern can
 * crash pcre2_compile().
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_9lqq1bms_osregex_bytes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

#include "shared.h"
#include "os_regex/os_regex.h"

static sigjmp_buf crash_jmp;
static volatile sig_atomic_t saw_crash;

static void crash_handler(int sig)
{
    (void)sig;
    saw_crash = 1;
    siglongjmp(crash_jmp, 1);
}

static int expect_regex(const char *label, const char *pattern, const char *subject,
                        int want)
{
    int got = OS_Regex(pattern, subject);

    if (got != want) {
        printf("FAIL: %s: OS_Regex returned %d (want %d) pattern='%s'\n",
               label, got, want, pattern);
        return 1;
    }
    printf("ok: %s\n", label);
    return 0;
}

static int expect_match(const char *label, const char *pattern, const char *subject,
                        int want)
{
    OSMatch reg;
    int got;

    memset(&reg, 0, sizeof(reg));
    if (!OSMatch_Compile(pattern, &reg, 0)) {
        printf("FAIL: %s: OSMatch_Compile failed (error=%d)\n", label, reg.error);
        return 1;
    }
    got = OSMatch_Execute(subject, strlen(subject), &reg);
    OSMatch_FreePattern(&reg);
    if (got != want) {
        printf("FAIL: %s: OSMatch_Execute returned %d (want %d)\n",
               label, got, want);
        return 1;
    }
    printf("ok: %s\n", label);
    return 0;
}

int main(void)
{
    int failed = 0;
    struct sigaction sa, old_segv, old_bus;
    const char *utf8_subj =
        "user 'admin' from 203.0.113.7 agent 'caf\xc3\xa9'";
    const char *latin1_subj =
        "user 'admin' from 203.0.113.7 agent 'caf\xe9'";
    char bad_pattern[] = { 'r', 'o', 'o', 't', '\xff', '\xfe', '\0' };

    printf("=== ANT-2026-9LQQ1BMS: classic regex matches bytes ===\n");

    failed |= expect_regex("utf-8 subject matches",
                           "from (\\S+) agent", utf8_subj, 1);
    failed |= expect_regex("latin-1 subject matches",
                           "from (\\S+) agent", latin1_subj, 1);
    failed |= expect_regex("latin-1 in matched text",
                           "agent '(\\S+)'$", latin1_subj, 1);
    failed |= expect_match("OSMatch latin-1 subject",
                           "caf\xe9", "xx caf\xe9 yy", 1);

    /* Invalid UTF-8 in the pattern must compile or fail cleanly, not crash. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    saw_crash = 0;
    if (sigsetjmp(crash_jmp, 1) == 0) {
        int rc = OS_Regex(bad_pattern, "root account");
        (void)rc;
        printf("ok: invalid-UTF-8 pattern did not crash (rc=%d)\n", rc);
    } else {
        printf("FAIL: invalid-UTF-8 pattern crashed the process\n");
        failed = 1;
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);

    if (failed) {
        printf("\nFAIL: issue_9lqq1bms_osregex_bytes\n");
        return 1;
    }

    printf("\nPASS: issue_9lqq1bms_osregex_bytes\n");
    return 0;
}
