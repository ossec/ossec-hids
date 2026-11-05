/*
 * ANT-2026-4T9F7XIQ: report_changes must keep one snapshot per file and
 * stop when the whole diff store reaches its quota. A deleted file's
 * snapshot goes with it.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_4t9f7xiq_diff_store
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "syscheckd/syscheck.h"

syscheck_config syscheck;

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static char tmpdir[] = "/tmp/ossec-4t9f7xiq-XXXXXX";

static int write_bytes(const char *path, size_t n, char byte)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char buf[256];
    size_t left;

    if (fd < 0) {
        return -1;
    }
    memset(buf, byte, sizeof(buf));
    for (left = n; left > 0; ) {
        size_t chunk = left > sizeof(buf) ? sizeof(buf) : left;

        if (write(fd, buf, chunk) != (ssize_t)chunk) {
            close(fd);
            return -1;
        }
        left -= chunk;
    }
    close(fd);
    return 0;
}

static int mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    char *slash;
    size_t len;

    len = strlen(path);
    if (len == 0 || len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, path, len + 1);
    for (slash = buf + 1; *slash; slash++) {
        if (*slash != '/') {
            continue;
        }
        *slash = '\0';
        if (mkdir(buf, 0755) < 0 && errno != EEXIST) {
            return -1;
        }
        *slash = '/';
    }
    if (mkdir(buf, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* Count state.* and diff.* under the snapshot directory. */
static int count_history(const char *dir)
{
    DIR *dp = opendir(dir);
    struct dirent *ent;
    int n = 0;

    if (!dp) {
        return -1;
    }
    while ((ent = readdir(dp)) != NULL) {
        if (strncmp(ent->d_name, "state.", 6) == 0 ||
                strncmp(ent->d_name, "diff.", 5) == 0) {
            n++;
        }
    }
    closedir(dp);
    return n;
}

int main(void)
{
    char file_a[PATH_MAX];
    char file_b[PATH_MAX];
    char file_c[PATH_MAX];
    char snap_a[PATH_MAX];
    char snap_b[PATH_MAX];
    char snap_c[PATH_MAX];
    char last_a[PATH_MAX];
    char last_b[PATH_MAX];
    char last_c[PATH_MAX];
    struct stat st;
    char *diff;

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    if (chdir(tmpdir) != 0) {
        perror("chdir");
        return 1;
    }
    if (mkdir("queue", 0755) != 0 || mkdir("queue/diff", 0755) != 0 ||
            mkdir("queue/diff/local", 0755) != 0 || mkdir("tmp", 0755) != 0) {
        perror("mkdir");
        return 1;
    }

    snprintf(file_a, sizeof(file_a), "%s/a.txt", tmpdir);
    snprintf(file_b, sizeof(file_b), "%s/b.txt", tmpdir);
    snprintf(file_c, sizeof(file_c), "%s/c.txt", tmpdir);
    /* Snapshot dir drops the leading slash of the absolute path. */
    snprintf(snap_a, sizeof(snap_a), "queue/diff/local%s", file_a);
    snprintf(snap_b, sizeof(snap_b), "queue/diff/local%s", file_b);
    snprintf(snap_c, sizeof(snap_c), "queue/diff/local%s", file_c);
    snprintf(last_a, sizeof(last_a), "%s/last-entry", snap_a);
    snprintf(last_b, sizeof(last_b), "%s/last-entry", snap_b);
    snprintf(last_c, sizeof(last_c), "%s/last-entry", snap_c);

    memset(&syscheck, 0, sizeof(syscheck));
    syscheck.diff_max_size = 4096;

    printf("leftover:\n");
    CHECK(write_bytes(file_c, 10, 'C') == 0, "write c");
    CHECK(mkdir_p(snap_c) == 0, "mkdir leftover snapshot dir");
    CHECK(write_bytes(last_c, 8192, 'Z') == 0, "plant oversized last-entry");

    printf("history:\n");
    CHECK(write_bytes(file_a, 80, 'A') == 0, "write a");
    diff = seechanges_addfile(file_a);
    free(diff);
    CHECK(stat(last_c, &st) != 0, "oversized leftover snapshot is dropped");
    CHECK(write_bytes(file_a, 80, 'B') == 0, "change a");
    diff = seechanges_addfile(file_a);
    CHECK(diff != NULL, "second change produces a diff");
    free(diff);
    CHECK(stat(last_a, &st) == 0, "last-entry kept");
    CHECK(count_history(snap_a) == 0, "state and diff files removed");

    printf("quota:\n");
    syscheck.diff_quota_size = 100;
    CHECK(write_bytes(file_b, 80, 'C') == 0, "write b");
    diff = seechanges_addfile(file_b);
    free(diff);
    CHECK(stat(last_b, &st) != 0, "over-quota file is not copied");

    printf("delete:\n");
    seechanges_delfile(file_a);
    CHECK(stat(last_a, &st) != 0, "snapshot removed with the file");
    diff = seechanges_addfile(file_b);
    free(diff);
    CHECK(stat(last_b, &st) == 0 && st.st_size == 80,
          "quota frees up after the snapshot is removed");

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
