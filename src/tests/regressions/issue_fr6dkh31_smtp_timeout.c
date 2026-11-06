/*
 * Regression: ossec-maild has no SMTP receive timeout
 *
 * ANT-2026-FR6DKH31 / CWE-400
 *
 * OS_Sendmail() reads every SMTP reply through a bare recv() with no
 * SO_RCVTIMEO. A relay that accepts and stays silent holds a sender
 * thread forever. After maild.max_workers such threads, no further
 * alert e-mail is sent until ossec-maild is restarted. A socket that
 * just connected must get a receive and send timeout before the banner
 * read, and OS_RecvTCP must return when that timeout expires.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_fr6dkh31_smtp_timeout
 *
 * Run:
 *   ./issue_fr6dkh31_smtp_timeout
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "shared.h"
#include "os_net/os_net.h"

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

static void alarm_exit(int sig)
{
    (void)sig;
    _exit(99);
}

static int make_connected_pair(int *client, int *peer)
{
    int listen_fd = -1;
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    int one = 1;

    *client = -1;
    *peer = -1;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return (0);
    }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
            listen(listen_fd, 1) < 0 ||
            getsockname(listen_fd, (struct sockaddr *)&addr, &alen) < 0) {
        close(listen_fd);
        return (0);
    }

    *client = socket(AF_INET, SOCK_STREAM, 0);
    if (*client < 0) {
        close(listen_fd);
        return (0);
    }
    if (connect(*client, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(*client);
        close(listen_fd);
        *client = -1;
        return (0);
    }
    *peer = accept(listen_fd, NULL, NULL);
    close(listen_fd);
    if (*peer < 0) {
        close(*client);
        *client = -1;
        return (0);
    }
    return (1);
}

static int file_has(const char *path, const char *needle)
{
    FILE *fp;
    char alt[256];
    char buf[4096];
    size_t n;
    size_t need = strlen(needle);
    size_t keep = 0;

    /* CI runs the binary from the repo root; local make runs it from src/. */
    fp = fopen(path, "r");
    if (!fp) {
        snprintf(alt, sizeof(alt), "src/%s", path);
        fp = fopen(alt, "r");
    }
    if (!fp) {
        return (0);
    }
    while ((n = fread(buf + keep, 1, sizeof(buf) - keep - 1, fp)) > 0) {
        size_t total = keep + n;
        size_t i;

        buf[total] = '\0';
        if (strstr(buf, needle)) {
            fclose(fp);
            return (1);
        }
        if (total > need) {
            memmove(buf, buf + total - need, need);
            keep = need;
        } else {
            keep = total;
        }
        (void)i;
    }
    fclose(fp);
    return (0);
}

int main(void)
{
    int client = -1;
    int peer = -1;
    struct timeval tv;
    socklen_t tvlen;
    char *msg;
    time_t started;
    time_t elapsed;

    printf("maild SMTP socket timeout\n");

    expect(make_connected_pair(&client, &peer),
           "open a connected pair on the loopback");
    if (client < 0) {
        printf("FAIL: could not open sockets\n");
        return 1;
    }

    expect(OS_SetSocketTimeout(client, 1) == 0,
           "OS_SetSocketTimeout returns success");

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    tvlen = sizeof(tv);
    if (getsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, &tvlen) == 0 &&
            tv.tv_sec == 1) {
        expect(1, "SO_RCVTIMEO is one second");
    } else {
        expect(0, "SO_RCVTIMEO is one second");
    }
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    tvlen = sizeof(tv);
    if (getsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, &tvlen) == 0 &&
            tv.tv_sec == 1) {
        expect(1, "SO_SNDTIMEO is one second");
    } else {
        expect(0, "SO_SNDTIMEO is one second");
    }

    /* Only exercise the timed read when the option was set. Otherwise a
     * silent peer would hang the harness forever.
     */
    if (failures == 0) {
        signal(SIGALRM, alarm_exit);
        alarm(3);
        started = time(NULL);
        msg = OS_RecvTCP(client, 64);
        elapsed = time(NULL) - started;
        alarm(0);
        expect(msg == NULL && elapsed >= 1 && elapsed < 3,
               "OS_RecvTCP returns when the receive timeout expires");
        free(msg);
    }

    close(client);
    close(peer);

    expect(file_has("os_maild/sendmail.c", "OS_SetSocketTimeout"),
           "OS_Sendmail / OS_Sendsms set the SMTP timeout");
    expect(file_has("os_maild/sendcustomemail.c", "OS_SetSocketTimeout"),
           "OS_SendCustomEmail sets the SMTP timeout");
    expect(file_has("monitord/sendcustomemail.c", "OS_SetSocketTimeout"),
           "monitord legacy SMTP sets the timeout");

    if (failures) {
        printf("FAIL: %d SMTP timeout check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
