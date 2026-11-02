/*
 * ANT-2026-ZO60J6E9: authd.pass blank / short first line must not disable
 * the enrollment password check.
 *
 * Invariant: claiming "using password from file" requires a non-NULL
 * authpass. A first line of "\n" historically left authpass NULL while
 * skipping the random-password fallback.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_zo60j6e9_authd_pass
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "os_auth/auth_pass.h"

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void check_blank_line_invariant(void)
{
    char buf[64];
    char *authpass;

    printf("--- blank first line (\"\\n\") ---\n");
    snprintf(buf, sizeof(buf), "\n");
    authpass = OS_AuthParsePassLine(buf);
    CHECK(authpass == NULL, "blank line does not yield authpass");
    /* Claiming the file password with no authpass is the bug. */
    CHECK(!OS_AuthUsingFilePassword(authpass, "\n"),
          "do not claim file password without authpass");
    free(authpass);
}

static void check_crlf_blank(void)
{
    char buf[64];
    char *authpass;

    printf("--- blank first line (\"\\r\\n\") ---\n");
    snprintf(buf, sizeof(buf), "\r\n");
    authpass = OS_AuthParsePassLine(buf);
    CHECK(authpass == NULL, "CRLF blank does not yield authpass");
    CHECK(!OS_AuthUsingFilePassword(authpass, "\r\n"),
          "do not claim file password without authpass (CRLF)");
    free(authpass);
}

static void check_normal_password(void)
{
    char buf[64];
    char *authpass;

    printf("--- normal password ---\n");
    snprintf(buf, sizeof(buf), "RealPassword123\n");
    authpass = OS_AuthParsePassLine(buf);
    CHECK(authpass != NULL && strcmp(authpass, "RealPassword123") == 0,
          "normal password is taken from the first line");
    CHECK(OS_AuthUsingFilePassword(authpass, "RealPassword123\n"),
          "claim file password when authpass is set");
    free(authpass);
}

static void check_short_password(void)
{
    char buf[64];
    char *authpass;

    printf("--- one-character password ---\n");
    snprintf(buf, sizeof(buf), "a\n");
    authpass = OS_AuthParsePassLine(buf);
    CHECK(authpass != NULL && strcmp(authpass, "a") == 0,
          "one-character password is accepted after strip");
    CHECK(OS_AuthUsingFilePassword(authpass, "a\n"),
          "claim file password for short authpass");
    free(authpass);
}

static void check_whitespace_only(void)
{
    char buf[64];
    char *authpass;

    printf("--- whitespace-only line ---\n");
    snprintf(buf, sizeof(buf), "   \n");
    authpass = OS_AuthParsePassLine(buf);
    CHECK(authpass == NULL, "whitespace-only line is not a password");
    CHECK(!OS_AuthUsingFilePassword(authpass, "   \n"),
          "do not claim file password for whitespace-only line");
    free(authpass);
}

static void check_leading_space_preserved(void)
{
    char buf[64];
    char *authpass;

    printf("--- leading space in password ---\n");
    snprintf(buf, sizeof(buf), " secret\n");
    authpass = OS_AuthParsePassLine(buf);
    CHECK(authpass != NULL && strcmp(authpass, " secret") == 0,
          "leading space in password is preserved");
    free(authpass);
}

int main(void)
{
    failures = 0;

    printf("=== ANT-2026-ZO60J6E9: authd.pass blank-line password ===\n");

    check_blank_line_invariant();
    check_crlf_blank();
    check_normal_password();
    check_short_password();
    check_whitespace_only();
    check_leading_space_preserved();

    if (failures) {
        printf("\nFAIL: issue_zo60j6e9_authd_pass (%d)\n", failures);
        return (1);
    }

    printf("\nPASS: issue_zo60j6e9_authd_pass\n");
    return (0);
}
