/*
 * Regression: ossec-execd drops a block while its delete is still running
 *
 * ANT-2026-8WBHQ0QF / CWE-362
 *
 * ExecdStart() forks the timeout "delete" and removes the list entry at
 * once. The next request for that script and address finds nothing, so
 * "add" runs beside "delete". A set-like target (hosts.deny, a PF table)
 * keeps the old block for "add" and then loses it to "delete", while
 * execd lists the address as blocked and skips every later request.
 *
 * The entry has to stay listed, with the child's pid, until that "delete"
 * is reaped. A request for the same script and address waits for it and
 * is then a new block. A request for a different address does not wait.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_8wbhq0qf_timeout_readd
 *
 * Run:
 *   ./issue_8wbhq0qf_timeout_readd
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shared.h"
#include "os_execd/execd.h"

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

static timeout_data *make_entry(const char *script, const char *user,
                                const char *ip, time_t added, int block_for)
{
    timeout_data *entry;

    os_calloc(1, sizeof(timeout_data), entry);
    os_calloc(5, sizeof(char *), entry->command);
    os_strdup(script, entry->command[0]);
    os_strdup("delete", entry->command[1]);
    os_strdup(user, entry->command[2]);
    os_strdup(ip, entry->command[3]);
    entry->time_of_addition = added;
    entry->time_to_block = block_for;
    entry->delete_pid = 0;
    return entry;
}

static timeout_data *find_ip(OSList *list, const char *ip)
{
    OSListNode *node;

    for (node = OSList_GetFirstNode(list); node;
            node = OSList_GetNextNode(list)) {
        timeout_data *entry = (timeout_data *)node->data;

        if (entry && entry->command && entry->command[3] &&
                strcmp(entry->command[3], ip) == 0) {
            return entry;
        }
    }
    return NULL;
}

static int write_sleeper(char *path, size_t pathlen)
{
    FILE *fp;
    int fd;

    snprintf(path, pathlen, "/tmp/ossec-8wbhq0qf-XXXXXX");
    fd = mkstemp(path);
    if (fd < 0) {
        return (0);
    }
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return (0);
    }
    fputs("#!/bin/sh\nsleep 2\n", fp);
    fclose(fp);
    if (chmod(path, 0700) != 0) {
        return (0);
    }
    return (1);
}

static void check_reap_removes_finished_delete(void)
{
    OSList *list;
    timeout_data *entry;
    pid_t pid;
    pid_t other;

    printf("reap a finished delete\n");
    list = OSList_Create();
    entry = make_entry("/bin/true", "-", "203.0.113.7", time(NULL), 600);
    other = (pid_t)4242;
    entry->delete_pid = other;
    OSList_AddData(list, entry);

    pid = fork();
    if (pid == 0) {
        _exit(0);
    }
    expect(pid > 0, "fork a delete child");
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        entry->delete_pid = pid;
        expect(ExecdTimeoutReapDelete(list, pid) == 1,
               "reaping the delete pid drops its entry");
        expect(find_ip(list, "203.0.113.7") == NULL,
               "the finished delete is no longer listed");
    }
}

static void check_expired_stays_until_delete_exits(void)
{
    OSList *list;
    timeout_data *kept;
    timeout_data *expired;
    timeout_data *still;
    char script[64];
    char *same[5];
    char *other[5];
    int childcount = 0;
    int added;
    time_t started;
    pid_t pid;

    printf("expired entry stays until delete exits\n");
    expect(write_sleeper(script, sizeof(script)), "write the delete stand-in");

    list = OSList_Create();
    kept = make_entry(script, "-", "198.51.100.1", time(NULL), 600);
    expired = make_entry(script, "-", "203.0.113.7", 0, 1);
    OSList_AddData(list, kept);
    OSList_AddData(list, expired);

    ExecdTimeoutLaunchDeletes(list, time(NULL), &childcount);

    expect(find_ip(list, "198.51.100.1") != NULL,
           "an entry that has not timed out stays listed");
    still = find_ip(list, "203.0.113.7");
    expect(still != NULL, "an expired entry stays listed while delete runs");
    expect(childcount == 1, "the delete child is counted");
    pid = still ? still->delete_pid : 0;
    expect(pid > 0 && kill(pid, 0) == 0, "the delete child is still running");

    if (still && pid > 0) {
        other[0] = script;
        other[1] = "add";
        other[2] = "-";
        other[3] = "198.51.100.9";
        other[4] = NULL;
        started = time(NULL);
        added = ExecdTimeoutDupCheck(list, other, time(NULL), NULL, &childcount);
        expect(added == 0 && (time(NULL) - started) < 2,
               "a different address does not wait for this delete");
        expect(find_ip(list, "203.0.113.7") != NULL,
               "the other address leaves the in-flight delete listed");

        same[0] = script;
        same[1] = "add";
        same[2] = "-";
        same[3] = "203.0.113.7";
        same[4] = NULL;
        alarm(10);
        added = ExecdTimeoutDupCheck(list, same, time(NULL), NULL, &childcount);
        alarm(0);
        expect(added == 0,
               "a request whose delete is still running is a new block");
        expect(find_ip(list, "203.0.113.7") == NULL,
               "the entry is dropped once that delete has exited");
        expect(childcount == 0, "waiting for the delete drops its child count");
    }

    if (pid > 0 && kill(pid, 0) == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    unlink(script);
}

int main(void)
{
    printf("execd timeout delete and re-add\n");
    check_reap_removes_finished_delete();
    check_expired_stays_until_delete_exits();

    if (failures) {
        printf("FAIL: %d timeout re-add check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
