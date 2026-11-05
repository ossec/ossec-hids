/*
 * ANT-2026-1O4BCXPR: CreatePID() must not follow a symlink planted in
 * var/run. That directory is group-writable, and the helper runs as root.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_1o4bcxpr_createpid
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static char tmpdir[] = "/tmp/ossec-1o4bcxpr-XXXXXX";

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    size_t n = strlen(text);

    if (fd < 0 || write(fd, text, n) != (ssize_t)n) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int read_text(const char *path, char *buf, size_t buflen)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0) {
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

int main(void)
{
    char secret[PATH_MAX];
    char pidpath[PATH_MAX];
    char got[64];
    struct stat st;
    mode_t secret_mode;

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    if (chdir(tmpdir) != 0 ||
            mkdir("var", 0770) != 0 || mkdir("var/run", 0770) != 0) {
        perror("setup");
        return 1;
    }

    snprintf(secret, sizeof(secret), "%s/secret.conf", tmpdir);
    /* DEFAULTDIR "." plus OS_PIDFILE "/var/run". */
    snprintf(pidpath, sizeof(pidpath), "%s/var/run/ossec-testd-4242.pid", tmpdir);

    printf("symlink:\n");
    CHECK(write_text(secret, "keep\n") == 0, "write secret");
    CHECK(stat(secret, &st) == 0, "stat secret");
    secret_mode = st.st_mode & 0777;
    CHECK(symlink(secret, "var/run/ossec-testd-4242.pid") == 0, "plant pid symlink");
    CHECK(CreatePID("ossec-testd", 4242) == 0, "CreatePID returns 0");

    CHECK(lstat(pidpath, &st) == 0 && S_ISREG(st.st_mode),
          "pid path is a regular file");
    CHECK((st.st_mode & 0777) == 0640, "pid file mode is 0640");
    CHECK(read_text(pidpath, got, sizeof(got)) == 0 && strcmp(got, "4242\n") == 0,
          "pid file contains the pid");
    CHECK(read_text(secret, got, sizeof(got)) == 0 && strcmp(got, "keep\n") == 0,
          "symlink target is not written");
    CHECK(stat(secret, &st) == 0 && (st.st_mode & 0777) == secret_mode,
          "symlink target mode is unchanged");

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
