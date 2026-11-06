/*
 * Regression: a renamed realtime directory keeps its old watch path
 *
 * ANT-2026-16QLZ097 / CWE-706
 *
 * realtime_adddir() stores a watch descriptor's path only the first time
 * it sees that descriptor. inotify follows the inode, so after a rename
 * the same descriptor comes back and events are built under the old name.
 * A stored name that still reaches the same directory (a symlink to it)
 * is kept.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_16qlz097_realtime_rename
 *
 * Run:
 *   ./issue_16qlz097_realtime_rename
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "syscheck.h"

const char *__local_name = "issue-16qlz097-realtime-rename";

/* realtime_adddir() references IsNFS. This test leaves skip_nfs off. */
short IsNFS(const char *dir_name)
{
    (void)dir_name;
    return 0;
}

syscheck_config syscheck;

static int failures = 0;
static char root[64];

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static int join(char *out, size_t outsz, const char *name)
{
    int n = snprintf(out, outsz, "%s/%s", root, name);

    if (n < 0 || (size_t)n >= outsz) {
        fprintf(stderr, "path too long: %s\n", name);
        return -1;
    }
    return 0;
}

/* The descriptor inotify already holds for this directory. */
static const char *stored_path(const char *dir)
{
    int wd;
    char wdchar[33];

    if (syscheck.realtime == NULL || syscheck.realtime->fd < 0) {
        return NULL;
    }
    wd = inotify_add_watch(syscheck.realtime->fd, dir, IN_MASK_ADD | IN_ATTRIB);
    if (wd < 0) {
        perror(dir);
        return NULL;
    }
    snprintf(wdchar, sizeof(wdchar), "%d", wd);
    return (const char *)OSHash_Get(syscheck.realtime->dirtb, wdchar);
}

/* Old name is gone: the watch must record the name the directory has now. */
static void test_rename_updates_path(void)
{
    char before[80];
    char after[80];
    const char *stored;

    printf("--- rename, old name removed ---\n");
    if (join(before, sizeof(before), "before") != 0 ||
            join(after, sizeof(after), "after") != 0 ||
            mkdir(before, 0755) != 0) {
        perror(before);
        failures++;
        return;
    }
    expect(realtime_adddir(before, 0) == 1, "first name is watched");
    if (rename(before, after) != 0) {
        perror("rename");
        failures++;
        return;
    }
    expect(realtime_adddir(after, 0) == 1, "new name is watched");
    stored = stored_path(after);
    expect(stored != NULL && strcmp(stored, after) == 0,
           "watch path is the directory's new name");
}

/* Old name is now a different directory: the moved one keeps its new name. */
static void test_old_name_recreated(void)
{
    char oldn[80];
    char newn[80];
    const char *stored;

    printf("--- old name recreated as a different directory ---\n");
    if (join(oldn, sizeof(oldn), "reold") != 0 ||
            join(newn, sizeof(newn), "renew") != 0 ||
            mkdir(oldn, 0755) != 0) {
        perror(oldn);
        failures++;
        return;
    }
    realtime_adddir(oldn, 0);
    if (rename(oldn, newn) != 0 || mkdir(oldn, 0755) != 0) {
        perror("recreate");
        failures++;
        return;
    }
    realtime_adddir(newn, 0);
    stored = stored_path(newn);
    expect(stored != NULL && strcmp(stored, newn) == 0,
           "moved directory is not left under the recreated name");
    rmdir(oldn);
}

/* A symlink left at the old name still reaches this directory, so it stays. */
static void test_symlink_keeps_old_name(void)
{
    char oldn[80];
    char newn[80];
    const char *stored;

    printf("--- symlink left at the old name ---\n");
    if (join(oldn, sizeof(oldn), "linkold") != 0 ||
            join(newn, sizeof(newn), "linknew") != 0 ||
            mkdir(oldn, 0755) != 0) {
        perror(oldn);
        failures++;
        return;
    }
    realtime_adddir(oldn, 0);
    if (rename(oldn, newn) != 0 || symlink(newn, oldn) != 0) {
        perror("symlink");
        failures++;
        return;
    }
    realtime_adddir(newn, 0);
    stored = stored_path(newn);
    expect(stored != NULL && strcmp(stored, oldn) == 0,
           "a name that still reaches the directory is kept");
    unlink(oldn);
}

/* Watching the same path again does not drop it. */
static void test_same_path_unchanged(void)
{
    char dir[80];
    const char *stored;

    printf("--- same path watched twice ---\n");
    if (join(dir, sizeof(dir), "same") != 0 || mkdir(dir, 0755) != 0) {
        perror(dir);
        failures++;
        return;
    }
    realtime_adddir(dir, 0);
    realtime_adddir(dir, 0);
    stored = stored_path(dir);
    expect(stored != NULL && strcmp(stored, dir) == 0,
           "watching the same path keeps that path");
}

int main(void)
{
    char tmpl[] = "/tmp/ossec-16qlz097-XXXXXX";

    if (mkdtemp(tmpl) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(root, sizeof(root), "%s", tmpl);
    memset(&syscheck, 0, sizeof(syscheck));

    test_rename_updates_path();
    test_old_name_recreated();
    test_symlink_keeps_old_name();
    test_same_path_unchanged();

    {
        char path[80];
        const char *names[] = {"after", "renew", "linknew", "same"};
        size_t i;

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            if (join(path, sizeof(path), names[i]) == 0) {
                rmdir(path);
            }
        }
    }
    if (syscheck.realtime != NULL && syscheck.realtime->fd >= 0) {
        close(syscheck.realtime->fd);
    }
    rmdir(root);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
