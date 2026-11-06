/*
 * Regression: ossec-dbd follows agent-info symlinks as root
 *
 * ANT-2026-5Z4OX04E / CWE-59
 *
 * __Agent_ReadInfo() stat()s and fopen()s queue/agent-info/<name>-<ip>.
 * That directory is writable by ossecr, and ossec-dbd runs as root, so a
 * symlink (or a hard link, when the kernel allows it) makes root copy the
 * first line of another file into the agent table.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_5z4ox04e_agent_info_symlink
 *
 * Run:
 *   ./issue_5z4ox04e_agent_info_symlink
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "os_dbd/dbd.h"
#include "config/dbd-config.h"

static int failures = 0;
static char all_sql[OS_SIZE_8192];

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static int capture_insert(void *db_conn, const char *query)
{
    size_t used;
    size_t add;

    (void)db_conn;
    if (!query) {
        return (1);
    }
    used = strlen(all_sql);
    add = strlen(query);
    if (used + add + 2 < sizeof(all_sql)) {
        memcpy(all_sql + used, query, add);
        all_sql[used + add] = '\n';
        all_sql[used + add + 1] = '\0';
    }
    return (1);
}

static int capture_select(void *db_conn, const char *query)
{
    (void)db_conn;
    (void)query;
    /* No existing row, so OS_Agents_InsertDB builds an INSERT. */
    return (0);
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

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    len = strlen(text);
    n = write(fd, text, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

static void on_alarm(int sig)
{
    (void)sig;
    printf("  FAIL: OS_Agents_InsertDB hung on a FIFO agent-info\n");
    fflush(stdout);
    _exit(1);
}

int main(void)
{
    DBConfig db;
    char info_real[256];
    char info_link[256];
    char info_hard[256];
    char info_fifo[256];
    char secret[256];
    const char *keep = "Linuxbox - OSSECv450\n";
    const char *hidden = "TOPSECRET - leaked\n";
    struct timespec times[2];

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("ossec-dbd agent-info symlink\n");

    if (ensure_dir("/tmp/ossec-5z4ox04e") != 0 ||
            ensure_dir(AGENTINFO_DIR) != 0) {
        return 1;
    }

    snprintf(secret, sizeof(secret), "/tmp/ossec-5z4ox04e/secret");
    snprintf(info_real, sizeof(info_real), "%s/agent2-10.0.0.6", AGENTINFO_DIR);
    snprintf(info_link, sizeof(info_link), "%s/agent1-10.0.0.5", AGENTINFO_DIR);
    snprintf(info_hard, sizeof(info_hard), "%s/agent3-10.0.0.7", AGENTINFO_DIR);
    snprintf(info_fifo, sizeof(info_fifo), "%s/agent4-10.0.0.8", AGENTINFO_DIR);
    unlink(info_real);
    unlink(info_link);
    unlink(info_hard);
    unlink(info_fifo);
    unlink(secret);

    if (write_file(secret, hidden) != 0 || write_file(info_real, keep) != 0) {
        return 1;
    }
    times[0].tv_sec = 1700000000;
    times[0].tv_nsec = 0;
    times[1] = times[0];
    if (utimensat(AT_FDCWD, secret, times, 0) != 0) {
        perror("utimensat");
        return 1;
    }
    if (symlink(secret, info_link) != 0) {
        perror("symlink");
        return 1;
    }
    if (link(secret, info_hard) != 0) {
        perror("link");
        return 1;
    }
    if (write_file(KEYS_FILE,
                   "001 agent1 10.0.0.5 abcdef\n"
                   "002 agent2 10.0.0.6 abcdef\n"
                   "003 agent3 10.0.0.7 abcdef\n") != 0) {
        return 1;
    }

    memset(&db, 0, sizeof(db));
    db.server_id = 1;
    db.conn = (void *)(intptr_t)1;
    osdb_query_insert = capture_insert;
    osdb_query_select = capture_select;
    all_sql[0] = '\0';

    OS_Agents_InsertDB(&db);
    expect(strstr(all_sql, "OSSECv450") != NULL,
           "a regular keepalive is stored");
    expect(strstr(all_sql, "TOPSECRET") == NULL,
           "a symlink target is not stored");
    expect(strstr(all_sql, "1700000000") == NULL,
           "a linked file's mtime is not stored as last_contact");

    /* A FIFO must not stall the agent refresh. */
    unlink(info_fifo);
    if (mkfifo(info_fifo, 0640) != 0) {
        perror("mkfifo");
        return 1;
    }
    if (write_file(KEYS_FILE, "004 agent4 10.0.0.8 abcdef\n") != 0) {
        return 1;
    }
    all_sql[0] = '\0';
    signal(SIGALRM, on_alarm);
    alarm(2);
    OS_Agents_InsertDB(&db);
    alarm(0);
    expect(strstr(all_sql, "TOPSECRET") == NULL, "FIFO agent-info is not read");
    unlink(info_fifo);

    unlink(info_real);
    unlink(info_link);
    unlink(info_hard);
    unlink(secret);
    unlink(KEYS_FILE);
    rmdir(AGENTINFO_DIR);
    rmdir("/tmp/ossec-5z4ox04e");

    if (failures) {
        printf("FAIL: %d agent-info link check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
