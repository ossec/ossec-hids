/*
 * ANT-2026-2138NB95: report_changes must not follow symlinks when
 * snapshotting file content for diffs.
 *
 * A local user under a report_changes directory can point a monitored
 * name at a root-only file (leaf symlink), or replace a parent directory
 * with a symlink so the same path string resolves elsewhere. Opening the
 * source by path followed those links and copied the secret into
 * queue/diff / alert diffs, bypassing <nodiff> on the real path.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_2138nb95_report_changes_symlink
 *
 * Compiled with -DDEFAULTDIR=\".\" so the harness can chdir into a temp
 * tree and use ./queue/diff as the store.
 */

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

static char tmpdir[] = "/tmp/ossec-2138nb95-XXXXXX";
static char orig_cwd[512];

static void wipe_store(void)
{
    char cmd[640];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s/queue/diff'", tmpdir);
    (void)system(cmd);
}

static int mkdir_p(const char *path, mode_t mode)
{
    char buf[512];
    char *p;
    size_t n;

    n = strlen(path);
    if (n == 0 || n >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, path, n + 1);
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, data, strlen(data)) != (ssize_t)strlen(data)) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int file_contains(const char *path, const char *needle)
{
    char buf[4096];
    FILE *fp;
    size_t n;

    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    if (n == 0) {
        return 0;
    }
    buf[n] = '\0';
    return (strstr(buf, needle) != NULL);
}

static void last_entry_path(char *out, size_t out_sz, const char *monitored)
{
    snprintf(out, out_sz, "%s/queue/diff/local/%s/last-entry",
             tmpdir, monitored + 1);
}

/* Leaf symlink retarget: first snapshot of link->decoy, then link->secret. */
static void case_leaf_symlink_retarget(void)
{
    char home[512];
    char decoy[512];
    char secret[512];
    char linkpath[512];
    char appdir[512];
    char last_entry[512];
    char *alert;

    printf("--- leaf symlink retarget ---\n");
    wipe_store();
    CHECK(mkdir_p("queue/diff/local", 0750) == 0, "mkdir queue/diff/local");

    snprintf(home, sizeof(home), "%s/home/attacker", tmpdir);
    snprintf(decoy, sizeof(decoy), "%s/mine", home);
    snprintf(appdir, sizeof(appdir), "%s/etc/app", tmpdir);
    snprintf(secret, sizeof(secret), "%s/api.key", appdir);
    snprintf(linkpath, sizeof(linkpath), "%s/link", home);

    CHECK(mkdir_p(home, 0755) == 0, "mkdir home/attacker");
    CHECK(mkdir_p(appdir, 0700) == 0, "mkdir etc/app");
    CHECK(write_file(decoy, "hello\n") == 0, "write decoy");
    CHECK(write_file(secret, "key = SECRETVALUE\n") == 0, "write secret");
    unlink(linkpath);
    CHECK(symlink(decoy, linkpath) == 0, "link -> decoy");

    alert = seechanges_addfile(linkpath);
    free(alert);
    last_entry_path(last_entry, sizeof(last_entry), linkpath);

    /* Unfixed: fopen follows the link and snapshots decoy (or after retarget,
     * the secret). Fixed: leaf symlink is refused before / during open. */
    if (access(last_entry, F_OK) == 0) {
        CHECK(file_contains(last_entry, "hello") ||
              !file_contains(last_entry, "SECRETVALUE"),
              "initial snapshot must not already be the secret");
    }

    unlink(linkpath);
    CHECK(symlink(secret, linkpath) == 0, "retarget link -> secret");

    alert = seechanges_addfile(linkpath);
    free(alert);

    CHECK(access(last_entry, F_OK) != 0 ||
          !file_contains(last_entry, "SECRETVALUE"),
          "retarget must not snapshot secret through the leaf link");
}

/* Parent dir replaced by a symlink after the first snapshot. */
static void case_parent_component_symlink(void)
{
    char www[512];
    char sub[512];
    char sub2[512];
    char file_in[512];
    char ssldir[512];
    char secret[512];
    char last_entry[512];
    char *alert;

    printf("--- parent component symlink ---\n");
    wipe_store();
    CHECK(mkdir_p("queue/diff/local", 0750) == 0, "mkdir queue/diff/local");

    snprintf(www, sizeof(www), "%s/srv/www", tmpdir);
    snprintf(sub, sizeof(sub), "%s/sub", www);
    snprintf(sub2, sizeof(sub2), "%s/sub2", www);
    snprintf(file_in, sizeof(file_in), "%s/private.key", sub);
    snprintf(ssldir, sizeof(ssldir), "%s/ssl", tmpdir);
    snprintf(secret, sizeof(secret), "%s/private.key", ssldir);

    CHECK(mkdir_p(sub, 0755) == 0, "mkdir srv/www/sub");
    CHECK(write_file(file_in, "user-key\n") == 0, "write user private.key");
    CHECK(mkdir_p(ssldir, 0700) == 0, "mkdir ssl");
    CHECK(write_file(secret, "ROOTONLY_PRIVATE\n") == 0, "write root private.key");

    alert = seechanges_addfile(file_in);
    free(alert);
    last_entry_path(last_entry, sizeof(last_entry), file_in);
    CHECK(file_contains(last_entry, "user-key"), "first snapshot is user file");

    CHECK(rename(sub, sub2) == 0, "mv sub -> sub2");
    CHECK(symlink(ssldir, sub) == 0, "ln -s ssl sub (parent swap)");

    /* Path string unchanged; open-by-path would follow into ssl/private.key. */
    alert = seechanges_addfile(file_in);
    free(alert);

    CHECK(!file_contains(last_entry, "ROOTONLY_PRIVATE"),
          "parent symlink must not snapshot root private.key");
    /* After a failed nofollow open the store may still hold the old snapshot. */
    CHECK(file_contains(last_entry, "user-key") ||
          access(last_entry, F_OK) != 0,
          "store must not hold the redirected secret");
}

#ifndef WIN32
static void case_fopen_regular_nofollow(void)
{
    char dir[512];
    char file[512];
    char linkpath[512];
    char parentlink[512];
    char through[512];
    FILE *fp;
    char buf[64];

    printf("--- fopen_regular_nofollow ---\n");

    snprintf(dir, sizeof(dir), "%s/nofollow", tmpdir);
    snprintf(file, sizeof(file), "%s/real.txt", dir);
    snprintf(linkpath, sizeof(linkpath), "%s/link.txt", dir);
    snprintf(parentlink, sizeof(parentlink), "%s/plink", tmpdir);
    snprintf(through, sizeof(through), "%s/real.txt", parentlink);

    CHECK(mkdir_p(dir, 0755) == 0, "mkdir nofollow");
    CHECK(write_file(file, "ok-content\n") == 0, "write real.txt");
    unlink(linkpath);
    CHECK(symlink(file, linkpath) == 0, "symlink to real.txt");

    fp = fopen_regular_nofollow(file);
    CHECK(fp != NULL, "opens a real regular file");
    if (fp) {
        CHECK(fgets(buf, sizeof(buf), fp) != NULL &&
              strcmp(buf, "ok-content\n") == 0,
              "reads expected content");
        fclose(fp);
    }

    errno = 0;
    fp = fopen_regular_nofollow(linkpath);
    CHECK(fp == NULL, "refuses a leaf symlink");

    unlink(parentlink);
    CHECK(symlink(dir, parentlink) == 0, "parent dir symlink");
    errno = 0;
    fp = fopen_regular_nofollow(through);
    CHECK(fp == NULL, "refuses a path with a symlink parent component");
}
#endif

int main(void)
{
    printf("=== ANT-2026-2138NB95: report_changes nofollow snapshots ===\n");

    memset(&syscheck, 0, sizeof(syscheck));

    if (!getcwd(orig_cwd, sizeof(orig_cwd))) {
        perror("getcwd");
        return 1;
    }
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    if (chdir(tmpdir) != 0) {
        perror("chdir tmpdir");
        return 1;
    }
    if (mkdir("tmp", 0750) != 0 || mkdir("queue", 0750) != 0) {
        perror("mkdir tmp/queue");
        return 1;
    }

#ifndef WIN32
    case_fopen_regular_nofollow();
#endif
    case_leaf_symlink_retarget();
    case_parent_component_symlink();

    wipe_store();
    chdir(orig_cwd);
    {
        char cmd[640];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
        (void)system(cmd);
    }

    if (failures) {
        printf("FAIL: issue_2138nb95_report_changes_symlink (%d)\n", failures);
        return 1;
    }
    printf("PASS: issue_2138nb95_report_changes_symlink\n");
    return 0;
}
