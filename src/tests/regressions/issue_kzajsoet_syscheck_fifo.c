/*
 * ANT-2026-KZAJSOET: hash helpers must refuse a FIFO without hanging.
 *
 * seechanges_addfile() / c_read_file() reach OS_SHA256_File and
 * OS_MD5_SHA1_File on paths a local user can replace with a FIFO. A
 * blocking fopen() parks single-threaded ossec-syscheckd forever.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_kzajsoet_syscheck_fifo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "shared.h"
#include "headers/defs.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static char tmpdir[] = "/tmp/ossec-kzajsoet-XXXXXX";

static void cleanup_tree(void)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/plain.txt", tmpdir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/evil.fifo", tmpdir);
    unlink(path);
    rmdir(tmpdir);
}

/* Child runs fn(path); parent kills if it does not exit in timeout_ms.
 * Returns wait status, or -2 on hang. */
static int child_run_status(int (*fn)(const char *), const char *path,
                            int timeout_ms)
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
        _exit(fn(path) == 0 ? 1 : 0); /* 0 = refused/failed as expected */
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
    return -2;
}

static int sha256_ok(const char *path)
{
    os_sha256 out;

    return OS_SHA256_File(path, out, OS_BINARY);
}

static int md5sha1_ok(const char *path)
{
    os_md5 md5;
    os_sha1 sha1;

    return OS_MD5_SHA1_File(path, md5, sha1, OS_BINARY);
}

int main(void)
{
    char plain[256];
    char fifo[256];
    int st;
    FILE *fp;

    printf("issue_kzajsoet_syscheck_fifo:\n");

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    atexit(cleanup_tree);

    snprintf(plain, sizeof(plain), "%s/plain.txt", tmpdir);
    snprintf(fifo, sizeof(fifo), "%s/evil.fifo", tmpdir);

    fp = fopen(plain, "w");
    CHECK(fp != NULL, "create plain file");
    if (fp) {
        fputs("hello\n", fp);
        fclose(fp);
    }

    CHECK(sha256_ok(plain) == 0, "OS_SHA256_File hashes a regular file");
    CHECK(md5sha1_ok(plain) == 0, "OS_MD5_SHA1_File hashes a regular file");

    CHECK(mkfifo(fifo, 0600) == 0, "create FIFO without a writer");

    st = child_run_status(sha256_ok, fifo, 1000);
    CHECK(st != -2, "OS_SHA256_File does not hang on a FIFO");
    CHECK(st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "OS_SHA256_File refuses a FIFO");

    st = child_run_status(md5sha1_ok, fifo, 1000);
    CHECK(st != -2, "OS_MD5_SHA1_File does not hang on a FIFO");
    CHECK(st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "OS_MD5_SHA1_File refuses a FIFO");

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
