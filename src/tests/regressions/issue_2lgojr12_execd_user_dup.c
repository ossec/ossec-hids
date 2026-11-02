/*
 * ANT-2026-2LGOJR12: execd duplicate check must include the user argument.
 * For disable-account the IP is always "-", so matching only script+IP
 * suppresses lockouts for every later account while one is pending.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_2lgojr12_execd_user_dup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "list_op.h"
#include "os_execd/execd.h"

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static timeout_data *make_pending(const char *name, const char *user,
                                  const char *ip)
{
    timeout_data *e;
    char **cmd;

    os_calloc(1, sizeof(*e), e);
    os_calloc(5, sizeof(char *), cmd);
    cmd[0] = strdup(name);
    cmd[1] = strdup("add");
    cmd[2] = strdup(user);
    cmd[3] = strdup(ip);
    cmd[4] = NULL;
    e->command = cmd;
    e->time_of_addition = time(NULL);
    e->time_to_block = 600;
    return (e);
}

static void check_different_users_same_dash_ip(void)
{
    OSList *list;
    timeout_data *pending;
    char *args[5];
    int added;

    printf("--- disable-account: different users, IP='-' ---\n");
    list = OSList_Create();
    CHECK(list != NULL, "create timeout list");
    pending = make_pending("disable-account", "carol", "-");
    CHECK(OSList_AddData(list, pending) != 0, "seed pending carol lock");

    args[0] = "disable-account";
    args[1] = "add";
    args[2] = "bob";
    args[3] = "-";
    args[4] = NULL;

    added = ExecdTimeoutDupCheck(list, args, time(NULL), NULL);
    CHECK(added == 0,
          "bob is not treated as a duplicate of pending carol");
}

static void check_same_user_still_duplicate(void)
{
    OSList *list;
    timeout_data *pending;
    char *args[5];
    int added;

    printf("--- same user+IP still duplicates ---\n");
    list = OSList_Create();
    CHECK(list != NULL, "create timeout list");
    pending = make_pending("disable-account", "carol", "-");
    CHECK(OSList_AddData(list, pending) != 0, "seed pending carol");

    args[0] = "disable-account";
    args[1] = "add";
    args[2] = "carol";
    args[3] = "-";
    args[4] = NULL;

    added = ExecdTimeoutDupCheck(list, args, time(NULL), NULL);
    CHECK(added == 1, "same user+IP remains a duplicate");
}

static void check_ip_keyed_unaffected(void)
{
    OSList *list;
    timeout_data *pending;
    char *args[5];
    int added;

    printf("--- IP-keyed host-deny (user='-') ---\n");
    list = OSList_Create();
    CHECK(list != NULL, "create timeout list");
    pending = make_pending("host-deny", "-", "203.0.113.7");
    CHECK(OSList_AddData(list, pending) != 0, "seed pending host-deny");

    args[0] = "host-deny";
    args[1] = "add";
    args[2] = "-";
    args[3] = "203.0.113.7";
    args[4] = NULL;
    added = ExecdTimeoutDupCheck(list, args, time(NULL), NULL);
    CHECK(added == 1, "same IP still duplicates for address-keyed AR");

    args[3] = "198.51.100.9";
    added = ExecdTimeoutDupCheck(list, args, time(NULL), NULL);
    CHECK(added == 0, "different IP is not a duplicate");
}

int main(void)
{
    failures = 0;

    printf("=== ANT-2026-2LGOJR12: execd user-keyed AR duplicate check ===\n");

    check_different_users_same_dash_ip();
    check_same_user_still_duplicate();
    check_ip_keyed_unaffected();

    if (failures) {
        printf("\nFAIL: issue_2lgojr12_execd_user_dup (%d)\n", failures);
        return (1);
    }

    printf("\nPASS: issue_2lgojr12_execd_user_dup\n");
    return (0);
}
