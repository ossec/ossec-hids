/*
 * ANT-2026-J8XF7LCX: whole-file reads in syscheckd must stop at a size
 * cap. A sparse file otherwise keeps the single thread in fread() until
 * EOF. report_changes copies use a smaller cap than checksums.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_j8xf7lcx_file_max_size
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "syscheckd/syscheck.h"

syscheck_config syscheck;

/* c_hash_file warns through this; stay quiet in the regression. */
int c_read_is_quiet(void)
{
    return 1;
}

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static char tmpdir[] = "/tmp/ossec-j8xf7lcx-XXXXXX";

static int write_bytes(const char *path, size_t n, char byte)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char buf[4096];
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

static void case_hash_cap(const char *path)
{
    os_md5 md5;
    os_sha1 sha1;
    os_sha256 sha256;
    int rc;

    printf("--- hash byte cap ---\n");
    CHECK(write_bytes(path, 64 * 1024, 'A') == 0, "write 64 KiB file");

    errno = 0;
    md5[0] = sha1[0] = sha256[0] = 'x';
    rc = OS_MD5_SHA1_SHA256_File(path, md5, sha1, sha256, OS_BINARY, 4096);
    CHECK(rc < 0 && errno == EFBIG, "64 KiB file with a 4096-byte cap returns EFBIG");

    errno = 0;
    rc = OS_MD5_SHA1_SHA256_File(path, md5, sha1, sha256, OS_BINARY, 0);
    CHECK(rc == 0 && sha256[0] != '\0', "max_size 0 still hashes the whole file");

    rc = OS_MD5_SHA1_SHA256_File(path, md5, sha1, sha256, OS_BINARY, 64 * 1024);
    CHECK(rc == 0, "a file of exactly max_size is hashed");

    errno = 0;
    rc = OS_SHA256_File_nofollow_max(path, sha256, OS_BINARY, 4096);
    CHECK(rc < 0 && errno == EFBIG,
          "stored-snapshot hasher stops at the diff cap");
}

static void case_sparse_precheck(const char *path)
{
    struct stat st;
    os_md5 md5;
    os_sha1 sha1;
    os_sha256 sha256;
    int fd;
    int rc;

    printf("--- sparse size pre-check ---\n");
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "open sparse file");
    if (fd < 0) {
        return;
    }
    CHECK(ftruncate(fd, 8 * 1024 * 1024) == 0, "truncate sparse file to 8 MiB");
    close(fd);
    CHECK(stat(path, &st) == 0 && st.st_size == 8 * 1024 * 1024,
          "sparse file reports st_size 8 MiB");

    syscheck.file_max_size = 4096;
    rc = c_hash_file(path, &st, md5, sha1, sha256);
    CHECK(rc == 1, "c_hash_file does not hash a file already over the cap");
    CHECK(strcmp(md5, "xxx") == 0 && strcmp(sha256, "xxx") == 0,
          "over-limit checksums stay xxx");
}

static void case_diff_cap(const char *dir)
{
    char small[512];
    char big[512];
    char last_small[512];
    char last_big[512];
    struct stat st;
    char *alert;

    printf("--- report_changes copy cap ---\n");
    snprintf(small, sizeof(small), "%s/small.txt", dir);
    snprintf(big, sizeof(big), "%s/big.txt", dir);
    CHECK(write_bytes(small, 100, 's') == 0, "write 100-byte file");
    CHECK(write_bytes(big, 64 * 1024, 'B') == 0, "write 64 KiB file for diff");

    syscheck.diff_max_size = 4096;

    alert = seechanges_addfile(small);
    free(alert);
    snprintf(last_small, sizeof(last_small),
             "%s/queue/diff/local/%s/last-entry", dir, small + 1);
    CHECK(stat(last_small, &st) == 0 && st.st_size == 100,
          "file under the diff cap is snapshotted");

    alert = seechanges_addfile(big);
    free(alert);
    snprintf(last_big, sizeof(last_big),
             "%s/queue/diff/local/%s/last-entry", dir, big + 1);
    CHECK(stat(last_big, &st) != 0 || st.st_size <= 4096,
          "file over the diff cap is not copied in full");

    /* A snapshot taken before the cap must be removed once the live
     * file is over the limit, so the expanded copy does not stay. */
    syscheck.diff_max_size = 0;
    alert = seechanges_addfile(big);
    free(alert);
    CHECK(stat(last_big, &st) == 0 && st.st_size == 64 * 1024,
          "unlimited cap stores the 64 KiB snapshot");
    syscheck.diff_max_size = 4096;
    alert = seechanges_addfile(big);
    free(alert);
    CHECK(stat(last_big, &st) != 0,
          "oversized snapshot is removed while the live file stays over the cap");

    /* A symlink planted as last-entry must not be opened for write. */
    {
        char victim[512];
        int vfd;

        snprintf(victim, sizeof(victim), "%s/victim", dir);
        vfd = open(victim, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CHECK(vfd >= 0, "create symlink target");
        if (vfd >= 0) {
            CHECK(write(vfd, "SECRET", 6) == 6, "write symlink target");
            close(vfd);
        }
        unlink(last_small);
        CHECK(symlink(victim, last_small) == 0, "plant last-entry symlink");
        CHECK(write_bytes(small, 100, 'z') == 0, "change file under the cap");
        alert = seechanges_addfile(small);
        free(alert);
        vfd = open(victim, O_RDONLY);
        if (vfd >= 0) {
            char got[8];
            ssize_t n = read(vfd, got, sizeof(got));
            close(vfd);
            CHECK(n == 6 && memcmp(got, "SECRET", 6) == 0,
                  "symlink last-entry is not truncated");
        } else {
            CHECK(0, "symlink last-entry is not truncated");
        }
    }
}

int main(void)
{
    char orig[512];
    char path[512];

    printf("=== ANT-2026-J8XF7LCX: cap whole-file reads ===\n");
    memset(&syscheck, 0, sizeof(syscheck));

    if (!getcwd(orig, sizeof(orig))) {
        perror("getcwd");
        return 1;
    }
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    if (chdir(tmpdir) != 0) {
        perror("chdir");
        return 1;
    }
    if (mkdir("tmp", 0750) != 0 || mkdir("queue", 0750) != 0 ||
            mkdir("queue/diff", 0750) != 0 || mkdir("queue/diff/local", 0750) != 0) {
        perror("mkdir store");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/blob", tmpdir);
    case_hash_cap(path);
    case_sparse_precheck(path);
    case_diff_cap(tmpdir);

    chdir(orig);
    {
        char cmd[640];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
        (void)system(cmd);
    }

    if (failures) {
        printf("FAIL: issue_j8xf7lcx_file_max_size (%d)\n", failures);
        return 1;
    }
    printf("PASS: issue_j8xf7lcx_file_max_size\n");
    return 0;
}
