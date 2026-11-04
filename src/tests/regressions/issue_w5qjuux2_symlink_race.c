/*
 * ANT-2026-W5QJUUX2: rootcheck directory walks must look entries up
 * relative to the open parent DIR (fstatat/openat/fdopendir with
 * O_NOFOLLOW / AT_SYMLINK_NOFOLLOW on dirfd(parent)), not by re-joining
 * and re-resolving a path from the root every time.
 *
 * read_sys_dir()/read_sys_file() (check_rc_sys.c) and rk_check_dir()
 * (common.c) used to lstat()/open()/opendir() each entry by
 * "<dir>/<name>" built fresh from the walked path. A local user who can
 * write to a directory under the scan (e.g. /tmp, /var/tmp, /dev/shm)
 * can rename it out from under the walker right after it was opendir()'d
 * and put a symlink -- or a ring of directories that are each a symlink
 * to the next -- in its place. Every subsequent lstat()/open()/opendir()
 * of its entries then resolves through the swapped-in symlink(s) instead
 * of the directory that was actually opened, and a ring never finishes.
 *
 * rk_lstat_entry()/rk_open_entry()/rk_opendir_entry() (rootcheck/common.c)
 * fix this by resolving each entry via fstatat()/openat()/fdopendir() on
 * dirfd(parent) -- the already-open directory's file descriptor -- which
 * keeps referring to the directory that was actually opened no matter
 * what happens to the path it was opened through.
 *
 * This harness checks, directly against those three helpers:
 *
 *   1. AT_SYMLINK_NOFOLLOW / O_NOFOLLOW semantics: a symlink entry is
 *      reported (and only openable) as a symlink, never silently
 *      followed to its target, whether looked up through a parent DIR
 *      or (the Windows / no-parent fallback) by path.
 *
 *   2. TOCTOU on the parent directory itself: once a directory has been
 *      opendir()'d, renaming it away and dropping a symlink (ring) in
 *      its place must not affect lookups done through the already-open
 *      DIR * (dirfd-relative), while the equivalent by-path lookup --
 *      what the pre-fix code did on every single entry -- now resolves
 *      through the attacker's symlink and fails/diverges.
 *
 * Build (from src/ after `make -f tests/regressions/Makefile`):
 *   make -f tests/regressions/Makefile issue_w5qjuux2_symlink_race
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "rootcheck.h"

/* common.c (linked directly, not via shared.a) references this global and
 * these symbols declared extern in rootcheck.h; only 'rootcheck' is
 * actually touched by the code paths this harness exercises, but all must
 * be defined to satisfy the linker for the whole translation unit.
 */
rkconfig rootcheck;
char **rk_sys_file;
char **rk_sys_name;
int rk_sys_count;

int notify_rk(int rk_type, const char *msg)
{
    (void)rk_type;
    (void)msg;
    return (0);
}

static char workdir[] = "/tmp/ossec-w5qjuux2-XXXXXX";
static int failed = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failed = 1; } \
    } while (0)

static void rm_tree(const char *path)
{
    char cmd[PATH_MAX + 64];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) {
        /* best-effort cleanup */
    }
}

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
        total += (size_t) nr;
    }
    buf[total] = '\0';
    return ((int) total);
}

/* Part 1: fstatat()/openat() through an open parent must never follow a
 * symlink entry -- same as lstat() for the last path component, and
 * provably different from what a following stat()/open() would see.
 */
static void test_symlink_not_followed(void)
{
    char base[PATH_MAX];
    char target_path[PATH_MAX];
    char link_path[PATH_MAX];
    DIR *parent;
    struct stat st_follow;
    struct stat st_rk;
    int fd;

    printf("=== Part 1: AT_SYMLINK_NOFOLLOW / O_NOFOLLOW semantics ===\n");

    snprintf(base, sizeof(base), "%s/part1", workdir);
    snprintf(target_path, sizeof(target_path), "%s/target_file", base);
    snprintf(link_path, sizeof(link_path), "%s/link_to_file", base);

    if (mkdir(base, 0755) < 0 ||
            write_file(target_path, "regular file contents\n") != 0 ||
            symlink("target_file", link_path) < 0) {
        perror("part1 setup");
        failed = 1;
        return;
    }

    /* Sanity: following the symlink (plain stat()) does reach a regular
     * file -- so if rk_lstat_entry() ever reported S_ISREG here, it would
     * prove the symlink had been followed.
     */
    if (stat(link_path, &st_follow) < 0) {
        perror("stat(link_path)");
        failed = 1;
        return;
    }
    CHECK(S_ISREG(st_follow.st_mode),
          "sanity: stat() on the symlink follows it to the regular file");

    parent = opendir(base);
    CHECK(parent != NULL, "opendir() on the parent directory");
    if (!parent) {
        return;
    }

    /* 1a. rk_lstat_entry() through the open parent must report the
     * symlink itself, not its target.
     */
    if (rk_lstat_entry(parent, "link_to_file", link_path, &st_rk) < 0) {
        perror("rk_lstat_entry(parent, link_to_file)");
        failed = 1;
    } else {
        CHECK(S_ISLNK(st_rk.st_mode),
              "rk_lstat_entry(parent,...) reports the symlink, not its target");
    }

    /* 1b. Same without a parent (path fallback) -- still must not follow. */
    if (rk_lstat_entry(NULL, NULL, link_path, &st_rk) < 0) {
        perror("rk_lstat_entry(NULL, link_to_file)");
        failed = 1;
    } else {
        CHECK(S_ISLNK(st_rk.st_mode),
              "rk_lstat_entry(NULL,...) path fallback also does not follow");
    }

    /* 1c. rk_open_entry() must refuse to open a symlink (O_NOFOLLOW),
     * where a plain open() would have happily followed it.
     */
    fd = open(link_path, O_RDONLY);
    CHECK(fd >= 0, "sanity: plain open() follows the symlink to the file");
    if (fd >= 0) {
        close(fd);
    }

    errno = 0;
    fd = rk_open_entry(parent, "link_to_file", link_path, O_RDONLY);
    CHECK(fd < 0 && errno == ELOOP,
          "rk_open_entry(parent,...) refuses the symlink (O_NOFOLLOW/ELOOP)");
    if (fd >= 0) {
        close(fd);
    }

    /* 1d. A directory entry that is actually a symlink to a directory
     * must not be openable as a directory either -- otherwise a
     * directory swapped for a symlink mid-walk would still get entered.
     */
    {
        char real_dir[PATH_MAX];
        char dir_link[PATH_MAX];
        DIR *dp;

        snprintf(real_dir, sizeof(real_dir), "%s/real_subdir", base);
        snprintf(dir_link, sizeof(dir_link), "%s/subdir_link", base);

        if (mkdir(real_dir, 0755) < 0 || symlink("real_subdir", dir_link) < 0) {
            perror("part1d setup");
            failed = 1;
        } else {
            dp = opendir(dir_link);
            CHECK(dp != NULL,
                  "sanity: plain opendir() follows a directory symlink");
            if (dp) {
                closedir(dp);
            }

            /* open(O_DIRECTORY|O_NOFOLLOW) on a symlink fails ELOOP on
             * some systems, ENOTDIR on others (observed on Linux here);
             * either way it must refuse, not follow the symlink.
             */
            errno = 0;
            dp = rk_opendir_entry(parent, "subdir_link", dir_link);
            CHECK(dp == NULL && (errno == ELOOP || errno == ENOTDIR),
                  "rk_opendir_entry(parent,...) refuses a directory symlink");
            if (dp) {
                closedir(dp);
            }
        }
    }

    closedir(parent);
}

/* Part 2: once a directory has been opendir()'d, renaming it away and
 * dropping a two-node symlink ring in its place must not affect entry
 * lookups done through the already-open DIR * (dirfd-relative) -- while
 * the equivalent by-path lookup, what every entry used before the fix,
 * now resolves through the attacker's ring and fails.
 */
static void test_parent_rename_toctou(void)
{
    char part2[PATH_MAX];
    char victim[PATH_MAX];
    char moved[PATH_MAX];
    char ring_b[PATH_MAX];
    char secret_path[PATH_MAX];
    DIR *dp;
    struct stat st;
    int fd;
    char buf[256];

    printf("=== Part 2: directory renamed to a symlink ring after opendir() ===\n");

    snprintf(part2, sizeof(part2), "%s/part2", workdir);
    snprintf(victim, sizeof(victim), "%s/victim", part2);
    snprintf(moved, sizeof(moved), "%s/victim_moved", part2);
    snprintf(ring_b, sizeof(ring_b), "%s/ring_b", part2);
    snprintf(secret_path, sizeof(secret_path), "%s/secret", victim);

    if (mkdir(part2, 0755) < 0 ||
            mkdir(victim, 0755) < 0 ||
            write_file(secret_path, "ORIGINAL") != 0) {
        perror("part2 setup");
        failed = 1;
        return;
    }

    /* Open the victim directory, as a walker would before reading it. */
    dp = opendir(victim);
    CHECK(dp != NULL, "opendir() on the directory before the attacker acts");
    if (!dp) {
        return;
    }

    /* Attacker: move the real directory aside, then put a two-node
     * symlink ring where it used to be -- the "ring of directories"
     * from the finding, shrunk to the minimum that still forces a
     * path-based lookup through a cycle instead of the real directory.
     */
    if (rename(victim, moved) < 0) {
        perror("rename(victim, moved)");
        failed = 1;
        closedir(dp);
        return;
    }
    if (symlink("ring_b", victim) < 0 || symlink("victim", ring_b) < 0) {
        perror("symlink ring setup");
        failed = 1;
        closedir(dp);
        return;
    }

    /* The pre-fix behaviour: look the entry up again by the same path
     * string the walker had built ("<dir>/secret"). 'victim' is now a
     * symlink into a cycle, so this must fail (ELOOP) instead of
     * reaching the real file -- this is the bug: every entry of a
     * directory the attacker swapped is looked up this way.
     */
    errno = 0;
    CHECK(lstat(secret_path, &st) < 0 && errno == ELOOP,
          "by-path lookup after the swap resolves through the symlink ring (ELOOP)");

    /* The fix: rk_lstat_entry()/rk_open_entry() through the DIR * that
     * was opened *before* the attacker acted are resolved via
     * fstatat()/openat() on dirfd(dp) -- bound to the directory's inode,
     * not its (now hijacked) path -- and must still see the real file.
     */
    if (rk_lstat_entry(dp, "secret", secret_path, &st) < 0) {
        perror("rk_lstat_entry(dp, secret) after swap");
        failed = 1;
    } else {
        CHECK(S_ISREG(st.st_mode),
              "rk_lstat_entry(dp,...) still sees the real file via dirfd");
    }

    fd = rk_open_entry(dp, "secret", secret_path, O_RDONLY);
    CHECK(fd >= 0, "rk_open_entry(dp,...) still opens the real file via dirfd");
    if (fd >= 0) {
        int n = read_all(fd, buf, sizeof(buf));
        close(fd);
        CHECK(n == (int) strlen("ORIGINAL") && strcmp(buf, "ORIGINAL") == 0,
              "content read through dirfd matches the pre-swap file, not the ring");
    }

    /* rk_opendir_entry() on the swapped name itself must refuse (it is
     * now a symlink into the ring, not a directory) rather than follow
     * it and let the walk wander into the ring.
     */
    {
        DIR *dp2 = opendir(workdir);
        DIR *bad;

        CHECK(dp2 != NULL, "opendir(workdir) to look up the swapped name");
        if (dp2) {
            closedir(dp2);
            dp2 = opendir(part2);
            CHECK(dp2 != NULL, "opendir(workdir/part2)");
            if (dp2) {
                errno = 0;
                bad = rk_opendir_entry(dp2, "victim", victim);
                CHECK(bad == NULL && (errno == ELOOP || errno == ENOTDIR),
                      "rk_opendir_entry() refuses to enter the symlink ring");
                if (bad) {
                    closedir(bad);
                }
                closedir(dp2);
            }
        }
    }

    closedir(dp);
}

int main(void)
{
    printf("=== ANT-2026-W5QJUUX2: dirfd-relative lookups vs. symlink races ===\n");

    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return (1);
    }
    memset(&rootcheck, 0, sizeof(rootcheck));

    test_symlink_not_followed();
    test_parent_rename_toctou();

    rm_tree(workdir);

    if (failed) {
        printf("\nFAIL: issue_w5qjuux2_symlink_race\n");
        return (1);
    }

    printf("\nPASS: issue_w5qjuux2_symlink_race\n");
    return (0);
}
