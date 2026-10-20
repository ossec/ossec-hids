/*
 * Regression for ANT-2026-TDAH6U83 / CWE-59:
 * root must not follow a symlink planted in the ossec-owned logs/
 * directory when appending to active-responses.log / ossec.log.
 *
 * open_log_append() opens with O_NOFOLLOW and accepts only a regular
 * file with a single link.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_logs_symlink_nofollow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "shared.h"
#include "headers/file_op.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static char tmpdir[] = "/tmp/ossec-tdah6u83-XXXXXX";

static void cleanup_tree(void)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/logs/active-responses.log", tmpdir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/logs/real.log", tmpdir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/outside", tmpdir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/logs", tmpdir);
    rmdir(path);
    rmdir(tmpdir);
}

int main(void)
{
    char logpath[256];
    char realpath_buf[256];
    char outside[256];
    int fd;
    struct stat st;
    char probe[] = "probe\n";

    printf("=== ANT-2026-TDAH6U83: open_log_append refuses symlinks ===\n");

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(logpath, sizeof(logpath), "%s/logs", tmpdir);
    if (mkdir(logpath, 0750) != 0) {
        perror("mkdir logs");
        cleanup_tree();
        return 1;
    }

    snprintf(outside, sizeof(outside), "%s/outside", tmpdir);
    fd = open(outside, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0, "create outside target file");
    if (fd >= 0) {
        close(fd);
    }

    snprintf(logpath, sizeof(logpath), "%s/logs/active-responses.log", tmpdir);
    snprintf(realpath_buf, sizeof(realpath_buf), "%s/logs/real.log", tmpdir);

    /* Regular file: open must succeed and write. */
    printf("--- regular file ---\n");
    fd = open_log_append(realpath_buf);
    CHECK(fd >= 0, "open_log_append on a new regular file");
    if (fd >= 0) {
        CHECK(write(fd, probe, sizeof(probe) - 1) == (ssize_t)(sizeof(probe) - 1),
              "write through open_log_append descriptor");
        close(fd);
        CHECK(stat(realpath_buf, &st) == 0 && S_ISREG(st.st_mode),
              "created path is a regular file");
    }

    /* Symlink in place of the log: must refuse (do not follow to outside). */
    printf("--- symlink ---\n");
    unlink(logpath);
    CHECK(symlink(outside, logpath) == 0, "plant symlink as active-responses.log");

    errno = 0;
    fd = open_log_append(logpath);
    CHECK(fd < 0, "open_log_append refuses a symlink");
    if (fd >= 0) {
        close(fd);
    } else {
        CHECK(errno == ELOOP || errno == EPERM || errno == EMLINK,
              "refusal errno is a link/special-file style error");
    }

    /* Outside target must stay empty if the open was refused. */
    {
        char buf[64];
        ssize_t n;

        fd = open(outside, O_RDONLY);
        CHECK(fd >= 0, "re-open outside target");
        if (fd >= 0) {
            n = read(fd, buf, sizeof(buf));
            close(fd);
            CHECK(n == 0, "symlink target received no append from open_log_append");
        }
    }

    cleanup_tree();

    if (failures) {
        printf("\nFAIL: issue_logs_symlink_nofollow (%d)\n", failures);
        return 1;
    }

    printf("\nPASS: issue_logs_symlink_nofollow\n");
    return 0;
}
