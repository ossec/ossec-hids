/*
 * Regression: manage_agents database cleanup follows ossec-owned symlinks
 *
 * ANT-2026-AJJELLSQ / CWE-59
 *
 * delete_syscheck() and delete_rootcheck() emptied each database with
 * fopen(..., "w"). Those directories belong to the unprivileged ossec
 * user, and manage_agents still runs as root, so a symlink in the last
 * component made root truncate or create the target. A hard link did
 * the same to the shared inode. Opening must not follow a link, must
 * not create a missing name, and must empty only a regular file that
 * has a single link.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ajjellsq_db_symlink
 *
 * Run:
 *   ./issue_ajjellsq_db_symlink
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "read-agents.h"

const char *__local_name __attribute__((weak)) = "issue-ajjellsq-db-symlink";

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0750) != 0 && errno != EEXIST) {
        perror(path);
        return -1;
    }
    return 0;
}

static int write_file(const char *path, const char *text)
{
    int fd;
    size_t len;
    ssize_t n;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    len = strlen(text);
    n = write(fd, text, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

static int contents_are(const char *path, const char *text)
{
    char buf[128];
    int fd;
    ssize_t n;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) {
        return 0;
    }
    buf[n] = '\0';
    return strcmp(buf, text) == 0;
}

static int path_missing(const char *path)
{
    struct stat st;

    return lstat(path, &st) < 0 && errno == ENOENT;
}

static void on_alarm(int sig)
{
    (void)sig;
    printf("  FAIL: delete_syscheck hung on a FIFO\n");
    fflush(stdout);
    _exit(1);
}

int main(void)
{
    char path[512];
    char victim[512];
    char created[512];
    char hard[512];
    char rk_victim[512];
    const char *keep = "configuration-bytes";
    const char *hard_bytes = "hard-bytes";
    const char *rk_bytes = "rk-bytes";

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("agent database cleanup does not follow links\n");

    if (ensure_dir("/tmp/ossec-ajjellsq") != 0 ||
            ensure_dir(SYSCHECK_DIR) != 0 ||
            ensure_dir(ROOTCHECK_DIR) != 0) {
        return 1;
    }

    snprintf(victim, sizeof(victim), "/tmp/ossec-ajjellsq/victim.conf");
    snprintf(created, sizeof(created), "/tmp/ossec-ajjellsq/created-by-root");
    snprintf(hard, sizeof(hard), "/tmp/ossec-ajjellsq/hard-src");
    snprintf(rk_victim, sizeof(rk_victim), "/tmp/ossec-ajjellsq/rk-victim");
    unlink(victim);
    unlink(created);
    unlink(hard);
    unlink(rk_victim);

    /* Planted symlink to an existing file, and one to a name that does
     * not exist yet. These are the Windows registry database names, so
     * the live syscheck file can stay a real database. */
    if (write_file(victim, keep) != 0) {
        return 1;
    }
    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck",
             SYSCHECK_DIR, "a", "1.2.3.4");
    unlink(path);
    if (write_file(path, "db-bytes") != 0) {
        return 1;
    }
    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck-registry",
             SYSCHECK_DIR, "a", "1.2.3.4");
    unlink(path);
    if (symlink(victim, path) != 0) {
        perror("symlink registry");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/.(%s) %s->syscheck-registry.cpt",
             SYSCHECK_DIR, "a", "1.2.3.4");
    unlink(path);
    if (symlink(created, path) != 0) {
        perror("symlink registry cpt");
        return 1;
    }

    expect(delete_syscheck("a", "1.2.3.4", 1) == 1, "delete_syscheck returns");
    expect(contents_are(victim, keep), "symlink target keeps its contents");
    expect(path_missing(created), "missing link target is not created");
    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck",
             SYSCHECK_DIR, "a", "1.2.3.4");
    expect(path_missing(path), "real syscheck database is removed");
    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck-registry",
             SYSCHECK_DIR, "a", "1.2.3.4");
    expect(path_missing(path), "registry symlink is removed");
    snprintf(path, sizeof(path), "%s/.(%s) %s->syscheck-registry.cpt",
             SYSCHECK_DIR, "a", "1.2.3.4");
    expect(path_missing(path), "registry checksum symlink is removed");

    /* Clearing in place still empties a real database and leaves the name. */
    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck",
             SYSCHECK_DIR, "b", "9.9.9.9");
    unlink(path);
    if (write_file(path, "hello-db") != 0) {
        return 1;
    }
    expect(delete_syscheck("b", "9.9.9.9", 0) == 1, "in-place clear returns");
    expect(contents_are(path, ""), "regular database is emptied");
    unlink(path);

    /* A second name for the same inode must not be truncated. */
    if (write_file(hard, hard_bytes) != 0) {
        return 1;
    }
    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck",
             SYSCHECK_DIR, "c", "8.8.8.8");
    unlink(path);
    if (link(hard, path) != 0) {
        perror("link");
        return 1;
    }
    expect(delete_syscheck("c", "8.8.8.8", 0) == 1, "hard-link clear returns");
    expect(contents_are(hard, hard_bytes), "hard-link target keeps its contents");
    expect(contents_are(path, hard_bytes), "hard-linked database is not emptied");
    unlink(path);
    unlink(hard);

    if (write_file(rk_victim, rk_bytes) != 0) {
        return 1;
    }
    snprintf(path, sizeof(path), "%s/(%s) %s->rootcheck",
             ROOTCHECK_DIR, "d", "7.7.7.7");
    unlink(path);
    if (symlink(rk_victim, path) != 0) {
        perror("symlink rootcheck");
        return 1;
    }
    expect(delete_rootcheck("d", "7.7.7.7", 1) == 1, "delete_rootcheck returns");
    expect(contents_are(rk_victim, rk_bytes), "rootcheck symlink target is unchanged");
    expect(path_missing(path), "rootcheck symlink is removed");

    snprintf(path, sizeof(path), "%s/(%s) %s->syscheck",
             SYSCHECK_DIR, "e", "6.6.6.6");
    unlink(path);
    if (mkfifo(path, 0640) != 0) {
        perror("mkfifo");
        return 1;
    }
    signal(SIGALRM, on_alarm);
    alarm(2);
    expect(delete_syscheck("e", "6.6.6.6", 1) == 1, "FIFO database does not block");
    alarm(0);
    expect(path_missing(path), "FIFO database name is removed");

    unlink(victim);
    unlink(created);
    unlink(rk_victim);
    rmdir(SYSCHECK_DIR);
    rmdir(ROOTCHECK_DIR);
    rmdir("/tmp/ossec-ajjellsq");

    if (failures) {
        printf("FAIL: %d database link check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
