/*
 * ANT-2026-RBAKY685: forged agent locations must not allocate permanent
 * syscheck/rootcheck DB slots. Only the names shipped senders use
 * (syscheck, syscheck-registry, rootcheck) may take a slot after "->".
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_rbaky685_syscheck_slot_exhaustion
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "eventinfo.h"
#include "config.h"
#include "rules.h"

const char *__local_name __attribute__((weak)) =
    "issue-rbaky685-syscheck-slot-exhaustion";

_Config Config;

int getDecoderfromlist(const char *name)
{
    if (!name) {
        return (0);
    }
    if (strcmp(name, ROOTCHECK_MOD) == 0) {
        return (200);
    }
    if (strcmp(name, SYSCHECK_MOD) == 0) {
        return (101);
    }
    if (strcmp(name, SYSCHECK_MOD2) == 0) {
        return (102);
    }
    if (strcmp(name, SYSCHECK_MOD3) == 0) {
        return (103);
    }
    if (strcmp(name, SYSCHECK_NEW) == 0) {
        return (104);
    }
    if (strcmp(name, SYSCHECK_DEL) == 0) {
        return (105);
    }
    return (1);
}

void SyscheckInit(void);
void RootcheckInit(void);
int Syscheck_TestSlotCount(void);
int Syscheck_TestOpenDB(const char *location);
int Rootcheck_TestSlotCount(void);
int Rootcheck_TestOpenDB(const char *location);

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static int mkdir_p(const char *path)
{
    char tmp[512];
    size_t len;
    size_t i;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    for (i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static void rm_tree(const char *path)
{
    char cmd[700];

    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", path);
    (void)system(cmd);
}

int main(void)
{
    char orig[512];
    char tmpl[] = "/tmp/ossec-rbaky685-XXXXXX";
    char *tmpdir;
    char loc[128];
    int i;
    int forged_slots;
    const int flood = 32;
    int exit_code = 1;

    printf("ANT-2026-RBAKY685 syscheck/rootcheck location slot allow-list\n");

    if (!getcwd(orig, sizeof(orig))) {
        perror("getcwd");
        return 1;
    }

    tmpdir = mkdtemp(tmpl);
    if (!tmpdir) {
        perror("mkdtemp");
        return 1;
    }
    if (chdir(tmpdir) != 0) {
        perror("chdir tmpdir");
        rm_tree(tmpdir);
        return 1;
    }

    if (mkdir_p("queue/syscheck") != 0 || mkdir_p("queue/rootcheck") != 0) {
        perror("mkdir queue");
        goto cleanup;
    }

    memset(&Config, 0, sizeof(Config));
    SyscheckInit();
    RootcheckInit();

    CHECK(Syscheck_TestSlotCount() == 0, "syscheck starts with empty slot table");
    CHECK(Rootcheck_TestSlotCount() == 0, "rootcheck starts with empty slot table");

    /* One agent invents many location suffixes after "->". */
    for (i = 0; i < flood; i++) {
        snprintf(loc, sizeof(loc), "(rogue) any->syscheck%d", i);
        (void)Syscheck_TestOpenDB(loc);
    }
    forged_slots = Syscheck_TestSlotCount();
    printf("  info: syscheck slots after %d forged locations = %d\n",
           flood, forged_slots);
    CHECK(forged_slots == 0,
          "forged syscheckN locations must not allocate DB slots");

    /* Legitimate agent locations still open. */
    CHECK(Syscheck_TestOpenDB("(web02) any->syscheck") == 1,
          "agent location ->syscheck allocates a slot");
    CHECK(Syscheck_TestOpenDB("(win01) any->syscheck-registry") == 1,
          "agent location ->syscheck-registry allocates a slot");
    CHECK(Syscheck_TestOpenDB("syscheck") == 1,
          "manager local location without -> still works");

    /* Embedded arrow in agent-chosen name must not pass as syscheck. */
    CHECK(Syscheck_TestOpenDB("(rogue) any->x->syscheck") == 0,
          "agent-chosen x->syscheck is refused");
    /* Arrow inside the agent name must not hide remoted's real separator. */
    CHECK(Syscheck_TestOpenDB("(evil->x) 10.1.2.3->syscheck") == 1,
          "agent name containing -> still opens ->syscheck");

    for (i = 0; i < flood; i++) {
        snprintf(loc, sizeof(loc), "(rogue) any->rootcheck%d", i);
        (void)Rootcheck_TestOpenDB(loc);
    }
    forged_slots = Rootcheck_TestSlotCount();
    printf("  info: rootcheck slots after %d forged locations = %d\n",
           flood, forged_slots);
    CHECK(forged_slots == 0,
          "forged rootcheckN locations must not allocate DB slots");

    CHECK(Rootcheck_TestOpenDB("(web02) any->rootcheck") == 1,
          "agent location ->rootcheck allocates a slot");
    CHECK(Rootcheck_TestOpenDB("rootcheck") == 1,
          "manager local rootcheck location without -> still works");
    CHECK(Rootcheck_TestOpenDB("(rogue) any->x->rootcheck") == 0,
          "agent-chosen x->rootcheck is refused");
    CHECK(Rootcheck_TestOpenDB("(evil->x) 10.1.2.3->rootcheck") == 1,
          "agent name containing -> still opens ->rootcheck");

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        exit_code = 1;
    } else {
        printf("PASS\n");
        exit_code = 0;
    }

cleanup:
    if (chdir(orig) != 0) {
        perror("chdir orig");
    }
    rm_tree(tmpdir);
    return exit_code;
}
