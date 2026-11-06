/*
 * Regression: realtime FIM treats a directory that replaced a known file
 * as a changed file and never scans it.
 *
 * ANT-2026-DXPIRJGM / CWE-754
 *
 * realtime_checksumfile() picks its path from syscheck.fp. A cached name
 * goes to c_read_file(), which has no directory case, so rm+mkdir under
 * the same name never reaches read_file() / read_dir() / realtime_adddir().
 * A cached path that is a directory now is a deleted file: report -1,
 * drop the entry only after that send succeeds, and scan it as a new path.
 *
 * c_read_file() and read_file() are supplied here so the branch choice is
 * visible without a syscheck queue. The directory itself is real.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_dxpirjgm_realtime_dir_replace
 *
 * Run:
 *   ./issue_dxpirjgm_realtime_dir_replace
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "syscheck.h"

int realtime_checksumfile(const char *file_name);

const char *__local_name = "issue-dxpirjgm-realtime-dir-replace";

syscheck_config syscheck;

static int failures = 0;
static int c_read_calls = 0;
static int read_file_calls = 0;
static int delfile_calls = 0;
static int last_read_opts = 0;
static char last_read_path[PATH_MAX];
static char messages[8][OS_MAXSTR + 1];
static int nmsg = 0;
static int send_rc = 0;

static char site[64];
static char uploads[80];
static char *dirs[2];
static int dir_opts[2];
static OSMatch *restricts[2];

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static void reset_obs(void)
{
    c_read_calls = 0;
    read_file_calls = 0;
    delfile_calls = 0;
    last_read_opts = 0;
    last_read_path[0] = '\0';
    nmsg = 0;
    memset(messages, 0, sizeof(messages));
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
        return -1;
    }
    fputs("known file\n", fp);
    fclose(fp);
    return 0;
}

int c_read_file(const char *file_name, const char *oldsum, char *newsum)
{
    (void)file_name;
    (void)oldsum;

    c_read_calls++;
    snprintf(newsum, OS_MAXSTR, "4096:16877:0:0:xxx:xxx:xxx");
    return 0;
}

int read_file(const char *file_name, int opts, OSMatch *restriction)
{
    (void)restriction;

    read_file_calls++;
    last_read_opts = opts;
    snprintf(last_read_path, sizeof(last_read_path), "%s", file_name);
    return 0;
}

char *seechanges_addfile(const char *filename)
{
    (void)filename;
    return NULL;
}

void seechanges_delfile(const char *filename)
{
    (void)filename;
    delfile_calls++;
}

int send_syscheck_msg(const char *msg)
{
    if (nmsg < 8) {
        snprintf(messages[nmsg], sizeof(messages[0]), "%s", msg);
        nmsg++;
    }
    return send_rc;
}

/* A file syscheck already knows, replaced by a directory, is deleted and scanned. */
static void test_dir_replaces_file(void)
{
    char want[96];

    printf("--- cached file replaced by a directory ---\n");
    if (write_file(uploads) != 0) {
        failures++;
        return;
    }
    cache_put(uploads);
    if (unlink(uploads) != 0 || mkdir(uploads, 0755) != 0) {
        perror(uploads);
        failures++;
        return;
    }

    reset_obs();
    send_rc = 0;
    realtime_checksumfile(uploads);

    snprintf(want, sizeof(want), "-1 %s", uploads);
    expect(c_read_calls == 0, "directory is not checksummed as a file");
    expect(read_file_calls == 1, "directory is scanned as a new path");
    expect(strcmp(last_read_path, uploads) == 0, "scan is of the replaced path");
    expect((last_read_opts & CHECK_REALTIME) != 0, "scan keeps realtime options");
    expect(nmsg >= 1 && strcmp(messages[0], want) == 0, "old file is reported deleted");
    expect(delfile_calls == 1, "report_changes snapshot is removed before the scan");
    expect(OSHash_Get(syscheck.fp, uploads) == NULL, "cache entry is dropped after the delete");
}

/* A failed delete send keeps the entry so the next event can retry it. */
static void test_delete_send_failure_keeps_cache(void)
{
    char want[96];

    printf("--- delete send failure keeps the cache entry ---\n");
    cache_put(uploads);
    reset_obs();
    send_rc = -1;
    realtime_checksumfile(uploads);

    snprintf(want, sizeof(want), "-1 %s", uploads);
    expect(nmsg >= 1 && strcmp(messages[0], want) == 0, "deletion is still attempted");
    expect(delfile_calls == 0, "snapshot stays when the delete was not delivered");
    expect(OSHash_Get(syscheck.fp, uploads) != NULL, "cache entry stays when the send fails");
    expect(read_file_calls == 1, "directory is still scanned");

    reset_obs();
    send_rc = 0;
    realtime_checksumfile(uploads);
    expect(nmsg >= 1 && strcmp(messages[0], want) == 0, "deletion is retried");
    expect(delfile_calls == 1, "snapshot is removed once the delete is delivered");
    expect(OSHash_Get(syscheck.fp, uploads) == NULL, "cache entry drops once the send succeeds");
}

/* A cached path that is still a file stays on the file path. */
static void test_file_still_uses_cache(void)
{
    int i;

    printf("--- cached file that is still a file ---\n");
    if (write_file(uploads) != 0) {
        failures++;
        return;
    }
    cache_put(uploads);
    reset_obs();
    send_rc = 0;
    realtime_checksumfile(uploads);

    expect(c_read_calls == 1, "an existing file is re-read");
    expect(read_file_calls == 0, "an existing file is not treated as new");
    expect(delfile_calls == 0, "a file change does not remove its snapshot");
    for (i = 0; i < nmsg; i++) {
        if (strncmp(messages[i], "-1 ", 3) == 0) {
            break;
        }
    }
    expect(i == nmsg, "an existing file is not reported deleted");
    expect(OSHash_Get(syscheck.fp, uploads) != NULL, "file cache entry remains");
}

/* A name syscheck has not seen is only the new-path scan. */
static void test_uncached_directory(void)
{
    char fresh[80];
    int i;

    printf("--- directory that was never cached ---\n");
    snprintf(fresh, sizeof(fresh), "%s/fresh", site);
    if (mkdir(fresh, 0755) != 0) {
        perror(fresh);
        failures++;
        return;
    }
    reset_obs();
    send_rc = 0;
    realtime_checksumfile(fresh);

    expect(c_read_calls == 0, "an uncached path does not use the file cache");
    expect(read_file_calls == 1, "an uncached directory is scanned");
    expect(delfile_calls == 0, "an uncached directory has no snapshot to remove");
    for (i = 0; i < nmsg; i++) {
        if (strncmp(messages[i], "-1 ", 3) == 0) {
            break;
        }
    }
    expect(i == nmsg, "an uncached directory is not a deletion");
    rmdir(fresh);
}

int main(void)
{
    char root[] = "/tmp/ossec-dxpirjgm-XXXXXX";

    if (mkdtemp(root) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(site, sizeof(site), "%s/site", root);
    snprintf(uploads, sizeof(uploads), "%s/uploads", site);
    if (mkdir(site, 0755) != 0) {
        perror(site);
        return 1;
    }

    memset(&syscheck, 0, sizeof(syscheck));
    syscheck.fp = OSHash_Create();
    if (syscheck.fp == NULL) {
        fprintf(stderr, "OSHash_Create failed\n");
        return 1;
    }
    dirs[0] = site;
    dirs[1] = NULL;
    dir_opts[0] = CHECK_REALTIME | CHECK_PERM | CHECK_SIZE;
    dir_opts[1] = 0;
    restricts[0] = NULL;
    restricts[1] = NULL;
    syscheck.dir = dirs;
    syscheck.opts = dir_opts;
    syscheck.filerestrict = restricts;

    test_dir_replaces_file();
    test_delete_send_failure_keeps_cache();
    if (rmdir(uploads) != 0) {
        perror(uploads);
        failures++;
    }
    test_file_still_uses_cache();
    unlink(uploads);
    test_uncached_directory();

    rmdir(site);
    rmdir(root);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
