/*
 * ANT-2026-X2IU8BSU: committing a mail batch must not wipe DONOTGROUP
 * placeholders that belong to a parked do_not_group alert (s_msg). Those
 * marks must become FULL_FORMAT so the held alert still reaches its
 * granular recipient (e.g. a pager).
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_x2iu8bsu_maild_donotgroup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "config/mail-config.h"
#include "os_maild/maild.h"

const char *__local_name = "issue-x2iu8bsu-maild-donotgroup";

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void setup_one_pager(MailConfig *mail, int mark)
{
    memset(mail, 0, sizeof(*mail));
    os_calloc(2, sizeof(char *), mail->gran_to);
    os_calloc(1, sizeof(int), mail->gran_set);
    mail->gran_to[0] = strdup("soc-pager@example.com");
    mail->gran_to[1] = NULL;
    mail->gran_set[0] = mark;
}

static void free_mail(MailConfig *mail)
{
    free(mail->gran_to[0]);
    free(mail->gran_to);
    free(mail->gran_set);
}

static void check_held_donotgroup_promoted(void)
{
    MailConfig mail;

    printf("--- held do_not_group: DONOTGROUP promoted ---\n");
    setup_one_pager(&mail, DONOTGROUP);

    Mail_CommitGranClear(&mail, 1);
    CHECK(mail.gran_set[0] == FULL_FORMAT,
          "DONOTGROUP becomes FULL_FORMAT while s_msg is held");

    free_mail(&mail);
}

static void check_no_hold_clears(void)
{
    MailConfig mail;

    printf("--- no held alert: marks cleared ---\n");
    setup_one_pager(&mail, DONOTGROUP);

    Mail_CommitGranClear(&mail, 0);
    CHECK(mail.gran_set[0] == 0,
          "DONOTGROUP cleared when nothing is held in s_msg");

    free_mail(&mail);
}

static void check_full_format_cleared_even_when_held(void)
{
    MailConfig mail;

    printf("--- held alert: unrelated FULL_FORMAT cleared ---\n");
    setup_one_pager(&mail, FULL_FORMAT);

    Mail_CommitGranClear(&mail, 1);
    CHECK(mail.gran_set[0] == 0,
          "batch FULL_FORMAT mark is cleared (not promoted)");

    free_mail(&mail);
}

int main(void)
{
    printf("=== ANT-2026-X2IU8BSU: Mail_CommitGranClear preserves DONOTGROUP ===\n");

    check_held_donotgroup_promoted();
    check_no_hold_clears();
    check_full_format_cleared_even_when_held();

    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
