/*
 * ANT-2026-MBH20U16: a syscheck walk must look each directory entry up
 * in the directory it was read from. Re-resolving "<dir>/<name>" from /
 * follows a symlink the user swapped in for that directory, so root
 * ossec-syscheckd reports a root-only file under the user's path.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_mbh20u16_dirfd_walk
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

static char workdir[] = "/tmp/ossec-mbh20u16-XXXXXX";
static int failed = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failed = 1; } \
    } while (0)

static int write_file(const char *path, const char *contents)
{
    FILE *fp = fopen(path, "w");

    if (!fp) {
        return (-1);
    }
    fputs(contents, fp);
    fclose(fp);
    return (0);
}

static int read_all(int fd, char *buf, size_t bufsz)
{
    ssize_t nr;
    size_t total = 0;

    while (total + 1 < bufsz) {
        nr = read(fd, buf + total, bufsz - 1 - total);
        if (nr <= 0) {
            break;
        }
        total += (size_t)nr;
    }
    buf[total] = '\0';
    return ((int)total);
}

/* The directory is opened, then replaced by a symlink to a root-only
 * tree that has the same entry name. Lookups through the open DIR must
 * still see the original file. */
static void test_open_dir_swapped(void)
{
    char base[PATH_MAX];
    char realdir[PATH_MAX];
    char parked[PATH_MAX];
    char secret[PATH_MAX];
    char real_file[PATH_MAX];
    char secret_file[PATH_MAX];
    char path[PATH_MAX];
    DIR *dp;
    struct stat st;
    int fd;
    char buf[64];

    printf("--- open directory replaced by a symlink ---\n");
    snprintf(base, sizeof(base), "%s/swap", workdir);
    snprintf(realdir, sizeof(realdir), "%s/d", base);
    snprintf(parked, sizeof(parked), "%s/parked", base);
    snprintf(secret, sizeof(secret), "%s/secret", base);
    snprintf(real_file, sizeof(real_file), "%s/key.txt", realdir);
    snprintf(secret_file, sizeof(secret_file), "%s/key.txt", secret);
    snprintf(path, sizeof(path), "%s/key.txt", realdir);

    if (mkdir(base, 0755) < 0 || mkdir(realdir, 0755) < 0 ||
            mkdir(secret, 0700) < 0 ||
            write_file(real_file, "user-file") != 0 ||
            write_file(secret_file, "root-only-secret") != 0) {
        perror("swap setup");
        failed = 1;
        return;
    }

    dp = opendir(realdir);
    CHECK(dp != NULL, "opendir the directory before it is swapped");
    if (!dp) {
        return;
    }
    if (rename(realdir, parked) < 0 || symlink(secret, realdir) < 0) {
        perror("swap");
        failed = 1;
        closedir(dp);
        return;
    }

    /* Sanity: the path now names the secret file. */
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "sanity: the path follows the symlink");
    if (fd >= 0) {
        int n = read_all(fd, buf, sizeof(buf));
        close(fd);
        CHECK(n > 0 && strcmp(buf, "root-only-secret") == 0,
              "sanity: the path reads the secret file");
    }

    if (fim_lstat_entry(dp, "key.txt", path, &st) < 0) {
        perror("fim_lstat_entry");
        failed = 1;
    } else {
        CHECK(S_ISREG(st.st_mode) && st.st_size == (off_t)strlen("user-file"),
              "lstat through the open directory sees the original file");
    }

    fd = fim_open_entry(dp, "key.txt", path, O_RDONLY);
    CHECK(fd >= 0, "open through the open directory");
    if (fd >= 0) {
        int n = read_all(fd, buf, sizeof(buf));
        close(fd);
        CHECK(n == (int)strlen("user-file") && strcmp(buf, "user-file") == 0,
              "read through the open directory is the original file");
    }

    closedir(dp);

    /* A symlink entry is followed from the opened directory, not by
     * walking the path that now points at the secret tree. */
    {
        char linkpath[PATH_MAX];
        char secret_link[PATH_MAX];

        snprintf(linkpath, sizeof(linkpath), "%s/link", parked);
        snprintf(secret_link, sizeof(secret_link), "%s/link", secret);
        snprintf(path, sizeof(path), "%s/link", realdir);
        if (symlink("key.txt", linkpath) != 0 ||
                symlink("key.txt", secret_link) != 0) {
            perror("symlink entry");
            failed = 1;
            return;
        }
        dp = opendir(parked);
        CHECK(dp != NULL, "reopen the original directory");
        if (dp) {
            fd = fim_open_entry_follow(dp, "link", path);
            CHECK(fd >= 0, "follow a symlink entry on the open directory");
            if (fd >= 0) {
                int n = read_all(fd, buf, sizeof(buf));
                close(fd);
                CHECK(n == (int)strlen("user-file") && strcmp(buf, "user-file") == 0,
                      "symlink entry follow reads the original target");
            }
            closedir(dp);
        }
    }
}

/* Realtime has no open DIR. A parent swapped for a symlink must not
 * be followed below the configured directory. */
static void test_monitored_parent_symlink(void)
{
    char base[PATH_MAX];
    char mon[PATH_MAX];
    char sub[PATH_MAX];
    char parked[PATH_MAX];
    char secret[PATH_MAX];
    char user_file[PATH_MAX];
    char secret_file[PATH_MAX];
    char path[PATH_MAX];
    char *dirs[2];
    struct stat st;
    FILE *fp;
    char buf[64];
    DIR *parent;
    DIR *child;

    printf("--- monitored path whose parent became a symlink ---\n");
    snprintf(base, sizeof(base), "%s/rt", workdir);
    snprintf(mon, sizeof(mon), "%s/home", base);
    snprintf(sub, sizeof(sub), "%s/e", mon);
    snprintf(parked, sizeof(parked), "%s/e-parked", mon);
    snprintf(secret, sizeof(secret), "%s/secret", base);
    snprintf(user_file, sizeof(user_file), "%s/key.txt", sub);
    snprintf(secret_file, sizeof(secret_file), "%s/key.txt", secret);
    snprintf(path, sizeof(path), "%s/key.txt", sub);

    if (mkdir(base, 0755) < 0 || mkdir(mon, 0755) < 0 ||
            mkdir(sub, 0755) < 0 || mkdir(secret, 0700) < 0 ||
            write_file(user_file, "user-file") != 0 ||
            write_file(secret_file, "root-only-secret") != 0) {
        perror("rt setup");
        failed = 1;
        return;
    }

    if (rename(sub, parked) < 0 || symlink(secret, sub) < 0) {
        perror("rt swap");
        failed = 1;
        return;
    }

    dirs[0] = mon;
    dirs[1] = NULL;
    syscheck.dir = dirs;

    errno = 0;
    CHECK(fim_lstat_monitored(path, &st) < 0 &&
              (errno == ELOOP || errno == ENOTDIR),
          "lstat below a configured directory does not follow the swapped parent");

    fp = fim_fopen_monitored(path, 0);
    CHECK(fp == NULL, "checksum open does not read through the swapped parent");
    if (fp) {
        if (fgets(buf, sizeof(buf), fp) && strstr(buf, "root-only")) {
            printf("  FAIL: checksum open read the secret file\n");
            failed = 1;
        }
        fclose(fp);
    }

    parent = opendir(mon);
    CHECK(parent != NULL, "opendir the configured directory");
    if (parent) {
        errno = 0;
        child = fim_opendir_entry(parent, "e", sub);
        CHECK(child == NULL && (errno == ELOOP || errno == ENOTDIR),
              "a subdirectory swapped for a symlink is not entered");
        if (child) {
            closedir(child);
        }
        closedir(parent);
    }
}

int main(void)
{
    char cmd[PATH_MAX + 32];

    printf("=== ANT-2026-MBH20U16: directory entries stay in the opened directory ===\n");
    memset(&syscheck, 0, sizeof(syscheck));
    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return (1);
    }

    test_open_dir_swapped();
    test_monitored_parent_symlink();

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", workdir);
    (void)system(cmd);

    if (failed) {
        printf("FAIL: issue_mbh20u16_dirfd_walk\n");
        return (1);
    }
    printf("PASS: issue_mbh20u16_dirfd_walk\n");
    return (0);
}
