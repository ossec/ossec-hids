/*
 * Regression: periodic FIM must report deletions without realtime.
 *
 * Antigravity Defect 6 / Windows (and Unix) periodic deletion blindspot.
 *
 * run_dbcheck() walks only names that still exist (readdir / FindFirstFile).
 * Cached paths that vanished between scans were never compared, so Rule 553
 * never fired unless realtime (inotify / ReadDirectoryChangesW) saw the
 * remove. syscheck_reconcile_missing() closes that gap after a complete walk.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_fim_periodic_delete
 *
 * Run:
 *   ./issue_fim_periodic_delete
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "syscheck.h"

const char *__local_name = "issue-fim-periodic-delete";

syscheck_config syscheck;

static int failures = 0;
static char messages[8][OS_MAXSTR + 1];
static int nmsg = 0;
static int send_rc = 0;
static int delfile_calls = 0;

static char site[64];
static char kept[80];
static char gone[80];

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

int send_syscheck_msg(const char *msg)
{
    if (nmsg < (int)(sizeof(messages) / sizeof(messages[0]))) {
        snprintf(messages[nmsg], sizeof(messages[0]), "%s", msg);
        nmsg++;
    }
    return (send_rc);
}

int send_rootcheck_msg(const char *msg)
{
    (void)msg;
    return (0);
}

void seechanges_delfile(const char *filename)
{
    (void)filename;
    delfile_calls++;
}

static void cache_put(const char *path)
{
    char *sum;

    if (OSHash_Get(syscheck.fp, path) != NULL) {
        free(OSHash_Delete(syscheck.fp, path));
    }
    sum = strdup("++++++-2:33188:0:0:xxx:xxx:xxx");
    if (sum == NULL || OSHash_Add(syscheck.fp, path, sum) != 2) {
        free(sum);
        fprintf(stderr, "OSHash_Add failed for %s\n", path);
        failures++;
    }
}

static int write_file(const char *path)
{
    FILE *fp = fopen(path, "w");

    if (fp == NULL) {
        perror(path);
        return (-1);
    }
    fputs("present\n", fp);
    fclose(fp);
    return (0);
}

static void reset_obs(void)
{
    nmsg = 0;
    delfile_calls = 0;
    memset(messages, 0, sizeof(messages));
}

static void test_missing_path_is_deleted(void)
{
    char expect_msg[PATH_MAX + 8];

    reset_obs();
    send_rc = 0;

    expect(write_file(kept) == 0, "kept file exists on disk");
    cache_put(kept);
    cache_put(gone);
    unlink(gone);

    syscheck_reconcile_missing(site);

    snprintf(expect_msg, sizeof(expect_msg), "-1 %s", gone);
    expect(nmsg == 1, "one delete alert is sent");
    expect(nmsg == 1 && strcmp(messages[0], expect_msg) == 0,
           "delete alert names the missing path");
    expect(OSHash_Get(syscheck.fp, gone) == NULL,
           "missing path is dropped from the cache");
    expect(OSHash_Get(syscheck.fp, kept) != NULL,
           "existing path stays in the cache");
#ifndef WIN32
    expect(delfile_calls == 1, "report_changes snapshot is cleared");
#endif
}

static void test_failed_send_keeps_cache(void)
{
    reset_obs();
    send_rc = -1;
    cache_put(gone);
    unlink(gone);

    syscheck_reconcile_missing(site);

    expect(nmsg == 1, "delete is attempted when send fails");
    expect(OSHash_Get(syscheck.fp, gone) != NULL,
           "cache entry remains when delivery fails");

    send_rc = 0;
    reset_obs();
    syscheck_reconcile_missing(site);
    expect(OSHash_Get(syscheck.fp, gone) == NULL,
           "retry drops the entry once the send succeeds");
}

static void test_sibling_dir_not_touched(void)
{
    char other[80];
    char other_file[96];

    snprintf(other, sizeof(other), "%s-other", site);
    snprintf(other_file, sizeof(other_file), "%s/x", other);

    reset_obs();
    send_rc = 0;
    mkdir(other, 0700);
    cache_put(other_file);
    unlink(other_file);

    syscheck_reconcile_missing(site);

    expect(nmsg == 0, "sibling tree is not reconciled");
    expect(OSHash_Get(syscheck.fp, other_file) != NULL,
           "sibling cache entry remains");

    free(OSHash_Delete(syscheck.fp, other_file));
    rmdir(other);
}

int main(void)
{
    snprintf(site, sizeof(site), "/tmp/ossec-fim-del-%d", (int)getpid());
    snprintf(kept, sizeof(kept), "%s/kept", site);
    snprintf(gone, sizeof(gone), "%s/gone", site);

    if (mkdir(site, 0700) != 0) {
        perror(site);
        return (1);
    }

    syscheck.fp = OSHash_Create();
    if (syscheck.fp == NULL || !OSHash_setSize(syscheck.fp, 32)) {
        fprintf(stderr, "OSHash_Create failed\n");
        return (1);
    }

    printf("issue_fim_periodic_delete\n");
    test_missing_path_is_deleted();
    test_failed_send_keeps_cache();
    test_sibling_dir_not_touched();

    unlink(kept);
    unlink(gone);
    rmdir(site);

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
