/*
 * Regression Test: Windows execd command injection via AR request fields
 *
 * ANT-2026-RYKB1OLI / CWE-78
 *
 * WinExecdRun() builds:
 *   "script" add "user" "ip" "rest..."
 * and CreateProcess hands the line to cmd.exe for .cmd responses. A '"' in
 * rest (event location) closes the quotes; '&' then starts another command.
 *
 * This test models that command-line construction (and, after the fix,
 * OS_WinExecdCleanArg on user/ip/rest) and a minimal cmd.exe parser
 * ('"' toggles quoting, '&' outside quotes separates commands).
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_win_execd_cmd_injection
 *
 * Run:
 *   ./issue_win_execd_cmd_injection
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "shared.h"

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

/* Count commands the way the scanner repro models cmd.exe. */
static int cmd_exe_command_count(const char *line)
{
    int n = 0;
    int in_quote = 0;
    const char *p = line;
    const char *start = NULL;

    while (*p != '\0') {
        if (*p == '"') {
            in_quote = !in_quote;
            if (!start) {
                start = p;
            }
            p++;
            continue;
        }
        if (*p == '&' && !in_quote) {
            if (start && p > start) {
                n++;
            }
            start = NULL;
            p++;
            while (*p == ' ') {
                p++;
            }
            continue;
        }
        if (!start && *p != ' ') {
            start = p;
        }
        p++;
    }
    if (start && *start != '\0') {
        n++;
    }
    return n;
}

static int cmd_exe_has_command(const char *line, const char *needle)
{
    int in_quote = 0;
    char cmd[OS_MAXSTR + 1];
    size_t n = 0;
    const char *p = line;

    while (*p != '\0') {
        if (*p == '"') {
            in_quote = !in_quote;
            p++;
            continue;
        }
        if (*p == '&' && !in_quote) {
            cmd[n] = '\0';
            if (n > 0 && strstr(cmd, needle) != NULL) {
                return 1;
            }
            n = 0;
            p++;
            while (*p == ' ') {
                p++;
            }
            continue;
        }
        if (n + 1 < sizeof(cmd)) {
            cmd[n++] = *p;
        }
        p++;
    }
    cmd[n] = '\0';
    return (n > 0 && strstr(cmd, needle) != NULL);
}

/* Same snprintf shape as WinExecdRun() after field split. */
static void build_ar_cmdline(char *buf, size_t buflen,
                             char *user, char *ip, char *rest)
{
    OS_WinExecdCleanArg(user);
    OS_WinExecdCleanArg(ip);
    OS_WinExecdCleanArg(rest);
    snprintf(buf, buflen, "\"%s\" %s \"%s\" \"%s\" \"%s\"",
             "active-response/bin/route-null.cmd", "add", user, ip, rest);
}

int main(void)
{
    char user[64];
    char ip[64];
    char rest[OS_MAXSTR + 1];
    char line[OS_MAXSTR + 1];

    printf("=== Windows execd cmd injection (ANT-2026-RYKB1OLI) ===\n");

    /* Benign control */
    printf("\n--- Control location ---\n");
    snprintf(user, sizeof(user), "%s", "-");
    snprintf(ip, sizeof(ip), "%s", "203.0.113.7");
    snprintf(rest, sizeof(rest), "%s",
             "1791872683.2 5701 (web01) any->/var/log/auth.log (null)");
    build_ar_cmdline(line, sizeof(line), user, ip, rest);
    CHECK(cmd_exe_command_count(line) == 1, "control is a single cmd.exe command");
    CHECK(!cmd_exe_has_command(line, "whoami"), "control has no whoami command");

    /* Crafted location from the finding */
    printf("\n--- Crafted location with quote-break ---\n");
    snprintf(user, sizeof(user), "%s", "-");
    snprintf(ip, sizeof(ip), "%s", "203.0.113.8");
    snprintf(rest, sizeof(rest), "%s",
             "1791872683.2 5701 (web01) any->/var/log/x\"&whoami>\\pwned&\" (null)");
    build_ar_cmdline(line, sizeof(line), user, ip, rest);
    printf("  cmdline: %s\n", line);
    CHECK(cmd_exe_command_count(line) == 1,
          "crafted location stays one cmd.exe command");
    CHECK(strstr(line, "x\"&") == NULL && strstr(line, "x_&whoami") != NULL,
          "quote-break neutralized; payload stays inside one argument");

    /* '%' must not survive for cmd.exe percent expansion */
    printf("\n--- Percent and control characters ---\n");
    snprintf(user, sizeof(user), "%s", "a%PATH%b");
    snprintf(ip, sizeof(ip), "%s", "1.2.3.4");
    snprintf(rest, sizeof(rest), "%s", "id loc\x0d\x0amore");
    build_ar_cmdline(line, sizeof(line), user, ip, rest);
    CHECK(strstr(line, "%PATH%") == NULL, "percent signs neutralized");
    CHECK(strchr(line, '\r') == NULL && strchr(line, '\n') == NULL,
          "CR/LF neutralized");

    printf("\n=== Test Result ===\n");
    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
