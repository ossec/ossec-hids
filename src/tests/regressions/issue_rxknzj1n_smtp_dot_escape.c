/*
 * ANT-2026-RXKNZJ1N: SMTP / sendmail body transparency for leading dots.
 *
 * A log line of "." becomes <CRLF>.<CRLF> in an alert body. Without RFC 5321
 * 4.5.2 doubling (SMTP) or ". " (sendmail pipe), DATA ends early and later
 * alerts in the batch are dropped or read as SMTP commands.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_rxknzj1n_smtp_dot_escape
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_maild/mail_utils.h"

const char *__local_name = "issue-rxknzj1n-smtp-dot-escape";

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void test_smtp_doubles_leading_dots(void)
{
    char dst[64];

    mail_escape_body_dots(".\r\na.b\r\n.\r\n.x\n.", dst, sizeof(dst), 1);
    CHECK(strcmp(dst, "..\r\na.b\r\n..\r\n..x\n..") == 0,
          "SMTP doubles every leading '.' (also after bare LF)");
}

static void test_pipe_spaces_lone_dot_lines(void)
{
    char dst[64];

    mail_escape_body_dots(".\r\na.b\r\n.\n.x\r\n..\r\n.", dst, sizeof(dst), 0);
    CHECK(strcmp(dst, ". \r\na.b\r\n. \n.x\r\n..\r\n. ") == 0,
          "sendmail pipe turns lone-dot lines into '. '");
}

static void test_truncation_drops_partial_escape(void)
{
    char small[6];

    mail_escape_body_dots("ab\r\n.\r\n", small, sizeof(small), 1);
    CHECK(strcmp(small, "ab\r\n") == 0,
          "dot + escape that will not fit is dropped together");
}

static void test_null_src(void)
{
    char dst[16];

    mail_escape_body_dots(NULL, dst, sizeof(dst), 1);
    CHECK(dst[0] == '\0', "NULL src yields empty destination");
}

int main(void)
{
    printf("issue_rxknzj1n_smtp_dot_escape:\n");
    test_smtp_doubles_leading_dots();
    test_pipe_spaces_lone_dot_lines();
    test_truncation_drops_partial_escape();
    test_null_src();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return (1);
    }
    printf("OK\n");
    return (0);
}
