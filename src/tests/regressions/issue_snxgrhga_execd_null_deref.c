/*
 * ANT-2026-SNXGRHGA: execd must not strcmp a NULL IP/user slot when an
 * incomplete AR request arrives while a timed response is pending.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_snxgrhga_execd_null_deref
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shared.h"
#include "list_op.h"
#include "os_execd/execd.h"

/* Defined in execd.c for production; provide a zero table for the unit. */
int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static timeout_data *make_pending(const char *name, const char *ip)
{
    timeout_data *e;
    char **cmd;

    os_calloc(1, sizeof(*e), e);
    os_calloc(5, sizeof(char *), cmd);
    cmd[0] = strdup(name);
    cmd[1] = strdup("add");
    cmd[2] = strdup("alice");
    cmd[3] = strdup(ip);
    cmd[4] = NULL;
    e->command = cmd;
    e->time_of_addition = time(NULL);
    e->time_to_block = 600;
    return (e);
}

static void free_pending(timeout_data *e)
{
    char **p;

    if (!e) {
        return;
    }
    p = e->command;
    if (p) {
        while (*p) {
            free(*p);
            p++;
        }
        free(e->command);
    }
    free(e);
}

/* Child runs the incomplete-request path; parent checks it survived. */
static int child_survives_incomplete_with_pending(void)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return (0);
    }

    if (pid == 0) {
        OSList *list;
        timeout_data *pending;
        char *args[5];
        int added;

        list = OSList_Create();
        if (!list) {
            _exit(2);
        }
        pending = make_pending("disable-account", "203.0.113.7");
        if (!OSList_AddData(list, pending)) {
            free_pending(pending);
            _exit(2);
        }

        /* Truncated request: name/add/user present, IP missing. */
        args[0] = "disable-account";
        args[1] = "add";
        args[2] = "bob";
        args[3] = NULL;
        args[4] = NULL;

        added = ExecdTimeoutDupCheck(list, args, time(NULL), NULL, NULL);
        /* Incomplete must be treated as dropped (added_before). */
        if (added != 1) {
            _exit(3);
        }
        _exit(0);
    }

    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return (0);
    }

    if (WIFSIGNALED(status)) {
        printf("  info: child died with signal %d\n", WTERMSIG(status));
        return (0);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("  info: child exit status %d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return (0);
    }
    return (1);
}

static void check_complete_still_matches(void)
{
    OSList *list;
    timeout_data *pending;
    char *args[5];
    int added;

    printf("--- complete request matches pending ---\n");
    list = OSList_Create();
    CHECK(list != NULL, "create timeout list");
    pending = make_pending("disable-account", "203.0.113.7");
    CHECK(OSList_AddData(list, pending) != 0, "seed pending timeout");

    args[0] = "disable-account";
    args[1] = "add";
    args[2] = "alice";
    args[3] = "203.0.113.7";
    args[4] = NULL;

    added = ExecdTimeoutDupCheck(list, args, time(NULL), NULL, NULL);
    CHECK(added == 1, "duplicate complete request is detected");
}

static void check_incomplete_no_crash(void)
{
    printf("--- incomplete request with pending timeout ---\n");
    CHECK(child_survives_incomplete_with_pending(),
          "incomplete AR request does not crash with pending timeout");
}

int main(void)
{
    failures = 0;

    printf("=== ANT-2026-SNXGRHGA: execd incomplete AR NULL deref ===\n");

    check_incomplete_no_crash();
    check_complete_still_matches();

    if (failures) {
        printf("\nFAIL: issue_snxgrhga_execd_null_deref (%d)\n", failures);
        return (1);
    }

    printf("\nPASS: issue_snxgrhga_execd_null_deref\n");
    return (0);
}
