/*
 * Regression: syslog_output placeholder check drops real field values
 *
 * ANT-2026-9Q8LR4NY / CWE-697
 *
 * field_add_string() and field_add_truncated() meant to skip placeholders
 * such as "(none)" and "(no user)". The test was written with && where
 * each alternative needs ||, so a value is dropped when any one character
 * lines up. A user named anna (second and third characters nn), a host
 * inn.example.org, and a location starting with "(n" never reach the
 * syslog receiver. The same indexes also read past a short string.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_9q8lr4ny_syslog_placeholder
 *
 * Run:
 *   ./issue_9q8lr4ny_syslog_placeholder
 */

#include <stdio.h>
#include <string.h>

#include "csyslogd.h"

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static void expect_string(const char *value, int present, const char *msg)
{
    char dest[OS_CSYSLOG_MAX];
    char needle[256];

    dest[0] = '\0';
    field_add_string(dest, sizeof(dest), " user: %s;", value);
    if (present) {
        snprintf(needle, sizeof(needle), " user: %s;", value);
        expect(strcmp(dest, needle) == 0, msg);
    } else {
        expect(dest[0] == '\0', msg);
    }
}

static void expect_truncated(const char *value, int present, const char *msg)
{
    char dest[OS_CSYSLOG_MAX];
    char needle[OS_CSYSLOG_MAX];

    dest[0] = '\0';
    field_add_truncated(dest, sizeof(dest), "  %s", value, 2);
    if (present) {
        snprintf(needle, sizeof(needle), "  %s", value);
        expect(strcmp(dest, needle) == 0, msg);
    } else {
        expect(dest[0] == '\0', msg);
    }
}

int main(void)
{
    char dest[OS_CSYSLOG_MAX];

    printf("syslog placeholder field filter\n");

    expect_string("bob", 1, "user bob is forwarded");
    expect_string("anna", 1, "user anna is forwarded");
    expect_string("anne", 1, "user anne is forwarded");
    expect_string("a", 1, "one-character user is forwarded");
    expect_string("unknown", 1, "user unknown is forwarded");
    expect_string("inn.example.org", 1, "host inn.example.org is forwarded");
    expect_string("(nginx01) 10.0.0.5->/var/log/auth.log", 1,
                  "location starting with (n is forwarded");
    expect_string("(web01) 10.0.0.5->/var/log/auth.log", 1,
                  "location (web01) is forwarded");

    expect_string("(none)", 0, "(none) is left out");
    expect_string("(no user)", 0, "(no user) is left out");

    expect_truncated("inn.example.org - - [11/Oct/2026:19:00:00 +0000] \"GET /x.php\"", 1,
                     "log text starting with inn.example.org is forwarded");
    expect_truncated("(none)", 0, "truncated (none) is left out");
    expect_truncated("(no user)", 0, "truncated (no user) is left out");

    dest[0] = '\0';
    expect(field_add_string(dest, sizeof(dest), " user: %s;", NULL) == 0,
           "NULL value adds nothing");
    expect(dest[0] == '\0', "NULL value leaves the buffer empty");

    if (failures) {
        printf("FAIL: %d syslog placeholder check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
