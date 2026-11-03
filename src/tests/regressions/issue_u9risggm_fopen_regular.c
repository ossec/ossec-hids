/*
 * Regression for ANT-2026-U9RISGGM / CWE-1322:
 * fopen_regular() must not hang on a FIFO (or accept a device). A monitored
 * log replaced by a FIFO used to park ossec-logcollector in open(2).
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_u9risggm_fopen_regular
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "shared.h"
#include "headers/file_op.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static char tmpdir[] = "/tmp/ossec-u9risggm-XXXXXX";

static void cleanup_tree(void)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/plain.log", tmpdir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/evil.fifo", tmpdir);
    unlink(path);
    rmdir(tmpdir);
}

/* Child opens path via fopen_regular; parent kills it if it does not exit. */
static int child_fopen_regular_status(const char *path, int timeout_ms)
{
    pid_t pid;
    int status = -1;
    int waited = 0;
    int r;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        FILE *fp = fopen_regular(path);

        if (fp != NULL) {
            fclose(fp);
            _exit(1); /* opened — wrong for FIFO/device cases */
        }
        _exit(0); /* refused */
    }

    while (waited < timeout_ms) {
        r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            return status;
        }
        if (r < 0) {
            perror("waitpid");
            return -1;
        }
        usleep(50 * 1000);
        waited += 50;
    }

    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -2; /* hung */
}

int main(void)
{
    char plain[256];
    char fifo[256];
    FILE *fp;
    int fd;
    int flags;
    int st;
    char buf[64];

    printf("=== ANT-2026-U9RISGGM: fopen_regular refuses FIFO/device ===\n");

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }

    snprintf(plain, sizeof(plain), "%s/plain.log", tmpdir);
    snprintf(fifo, sizeof(fifo), "%s/evil.fifo", tmpdir);

    /* Regular file: must open, allow reads, and leave O_NONBLOCK clear. */
    printf("--- regular file ---\n");
    fd = open(plain, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "create plain.log");
    if (fd >= 0) {
        CHECK(write(fd, "line\n", 5) == 5, "seed plain.log");
        close(fd);
    }

    errno = 0;
    fp = fopen_regular(plain);
    CHECK(fp != NULL, "fopen_regular opens a regular file");
    if (fp) {
        fd = fileno(fp);
        flags = fcntl(fd, F_GETFL);
        CHECK(flags != -1 && !(flags & O_NONBLOCK),
              "O_NONBLOCK cleared after accept");
        CHECK(fgets(buf, sizeof(buf), fp) != NULL && strcmp(buf, "line\n") == 0,
              "can read through fopen_regular FILE*");
        fclose(fp);
    }

    /* FIFO with no writer: must refuse quickly (not hang in open). */
    printf("--- FIFO ---\n");
    unlink(fifo);
    CHECK(mkfifo(fifo, 0644) == 0, "plant evil.fifo");

    st = child_fopen_regular_status(fifo, 1000);
    CHECK(st != -2, "fopen_regular does not hang on a FIFO");
    if (st != -2) {
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "fopen_regular refuses a FIFO (child exit 0)");
    }

    /* Character device: must refuse (O_NOCTTY + S_ISREG). */
    printf("--- device ---\n");
    if (access("/dev/null", R_OK) == 0) {
        st = child_fopen_regular_status("/dev/null", 1000);
        CHECK(st != -2, "fopen_regular does not hang on /dev/null");
        if (st != -2) {
            CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
                  "fopen_regular refuses /dev/null");
        }
        errno = 0;
        fp = fopen_regular("/dev/null");
        CHECK(fp == NULL && errno == EINVAL,
              "refuses /dev/null with errno EINVAL");
        if (fp) {
            fclose(fp);
        }
    } else {
        printf("  skip: /dev/null not readable\n");
    }

    cleanup_tree();

    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
