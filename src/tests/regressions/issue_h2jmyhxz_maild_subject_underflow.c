/*
 * ANT-2026-H2JMYHXZ: OS_RecvMailQ must not write before location[-1] when
 * cutting the hostname for the mail subject.
 *
 * A location that starts with '>' (ASL [Host >x], or a forged ** Alert
 * location line) made strchr(location, '>') + subject_host-- store one
 * byte before the heap string and abort ossec-maild on free().
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_h2jmyhxz_maild_subject_underflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_maild/mail_utils.h"

const char *__local_name = "issue-h2jmyhxz-maild-subject-underflow";

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

/* Layout: [canary][location\0]. Cut must never touch the canary. */
static void test_leading_gt_no_underflow(void)
{
    char buf[128];
    char *loc;
    char *cut;
    const char *payload = ">macmini->(agent01) 127.0.0.1->/var/log/system.log";

    memset(buf, 0, sizeof(buf));
    buf[0] = 'X';
    loc = buf + 1;
    memcpy(loc, payload, strlen(payload) + 1);

    cut = mail_subject_host_cut(loc);
    CHECK(buf[0] == 'X', "leading '>' must not write before location");
    CHECK(cut != NULL, "cut finds '->' after leading '>' hostname");
    CHECK(strcmp(loc, ">macmini") == 0, "subject keeps leading '>' hostname only");

    mail_subject_host_restore(cut);
    CHECK(buf[0] == 'X', "restore must not write before location");
    CHECK(strcmp(loc, payload) == 0, "restore puts back full location");
}

static void test_normal_separator(void)
{
    char loc[128];
    char *cut;
    const char *payload = "host.example->/var/log/secure";

    memcpy(loc, payload, strlen(payload) + 1);
    cut = mail_subject_host_cut(loc);
    CHECK(cut != NULL, "normal location finds '->'");
    CHECK(strcmp(loc, "host.example") == 0, "subject is hostname only");
    mail_subject_host_restore(cut);
    CHECK(strcmp(loc, payload) == 0, "restore restores '->' for body");
}

static void test_lone_gt_no_cut(void)
{
    char buf[32];
    char *loc;
    char *cut;

    memset(buf, 0, sizeof(buf));
    buf[0] = 'X';
    loc = buf + 1;
    memcpy(loc, ">", 2);

    cut = mail_subject_host_cut(loc);
    CHECK(buf[0] == 'X', "lone '>' must not underflow");
    CHECK(cut == NULL, "lone '>' has no '->' separator to cut");
    CHECK(strcmp(loc, ">") == 0, "lone '>' location unchanged");
}

static void test_null_location(void)
{
    CHECK(mail_subject_host_cut(NULL) == NULL, "NULL location returns NULL");
    mail_subject_host_restore(NULL);
}

int main(void)
{
    printf("ANT-2026-H2JMYHXZ maild subject-host underflow\n");
    test_leading_gt_no_underflow();
    test_normal_separator();
    test_lone_gt_no_cut();
    test_null_location();

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
