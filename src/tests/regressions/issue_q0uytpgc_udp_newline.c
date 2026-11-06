/*
 * Regression: UDP syslog_output keeps newlines inside one alert
 *
 * ANT-2026-Q0UYTPGC / CWE-117
 *
 * csyslog_send() replaced CR and LF with spaces only for TCP. The UDP
 * path, the default transport, sent the breaks. A receiver that splits a
 * datagram at newlines can store one of those lines as its own alert.
 * Every transport flattens the payload. Only TCP appends a trailing
 * newline.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_q0uytpgc_udp_newline
 *
 * Run:
 *   ./issue_q0uytpgc_udp_newline
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "csyslogd.h"

const char *__local_name = "issue-q0uytpgc-udp-newline";

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

static int bind_loopback(int type, char *port, size_t portlen)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    struct timeval tv;

    fd = socket(AF_INET, type, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) < 0) {
        close(fd);
        return -1;
    }
    snprintf(port, portlen, "%u", (unsigned)ntohs(addr.sin_port));

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static void fill_cfg(SyslogConfig *cfg, unsigned int protocol, char *port)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->server = "127.0.0.1";
    cfg->port = port;
    cfg->protocol = protocol;
    cfg->socket = -1;
}

static int recv_frame(int fd, char *buf, size_t buflen, size_t *n)
{
    ssize_t got;

    got = recv(fd, buf, buflen - 1, 0);
    if (got < 0) {
        return -1;
    }
    buf[got] = '\0';
    *n = (size_t)got;
    return 0;
}

static int no_break(const char *buf, size_t n, int allow_final_lf)
{
    size_t i;
    size_t end = n;

    if (allow_final_lf) {
        if (n == 0 || buf[n - 1] != '\n') {
            return 0;
        }
        end = n - 1;
    }
    for (i = 0; i < end; i++) {
        if (buf[i] == '\n' || buf[i] == '\r') {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    char port[16];
    char buf[OS_CSYSLOG_MAX + 8];
    char *big;
    const char *msg =
        "alpha\r\n<132>Oct 12 03:00:00 manager ossec: Alert Level: 15\nomega";
    const char *flat =
        "alpha  <132>Oct 12 03:00:00 manager ossec: Alert Level: 15 omega";
    SyslogConfig cfg;
    int fd;
    int accepted = -1;
    size_t n = 0;
    size_t i;

    printf("issue_q0uytpgc_udp_newline\n");

    fd = bind_loopback(SOCK_DGRAM, port, sizeof(port));
    expect(fd >= 0, "udp socket bound");
    if (fd >= 0) {
        fill_cfg(&cfg, CSYSLOG_UDP, port);
        expect(csyslog_send(&cfg, msg, strlen(msg)) == 0, "udp send succeeds");
        expect(recv_frame(fd, buf, sizeof(buf), &n) == 0, "udp datagram received");
        expect(n == strlen(flat) && memcmp(buf, flat, n) == 0,
               "udp datagram flattens CR and LF and adds no trailing newline");
        expect(no_break(buf, n, 0), "udp datagram has no line break");
        csyslog_close(&cfg);
        close(fd);
    }

    fd = bind_loopback(SOCK_DGRAM, port, sizeof(port));
    expect(fd >= 0, "plain udp socket bound");
    if (fd >= 0) {
        fill_cfg(&cfg, CSYSLOG_UDP, port);
        expect(csyslog_send(&cfg, "hello", 5) == 0, "plain udp send succeeds");
        expect(recv_frame(fd, buf, sizeof(buf), &n) == 0, "plain udp datagram received");
        expect(n == 5 && memcmp(buf, "hello", 5) == 0,
               "udp payload without a break is unchanged");
        csyslog_close(&cfg);
        close(fd);
    }

    fd = bind_loopback(SOCK_STREAM, port, sizeof(port));
    expect(fd >= 0 && listen(fd, 1) == 0, "tcp socket listening");
    if (fd >= 0) {
        fill_cfg(&cfg, CSYSLOG_TCP, port);
        expect(csyslog_send(&cfg, msg, strlen(msg)) == 0, "tcp send succeeds");
        accepted = accept(fd, NULL, NULL);
        expect(accepted >= 0, "tcp connection accepted");
        if (accepted >= 0) {
            expect(recv_frame(accepted, buf, sizeof(buf), &n) == 0,
                   "tcp frame received");
            expect(n == strlen(flat) + 1 &&
                       memcmp(buf, flat, strlen(flat)) == 0 &&
                       buf[n - 1] == '\n',
                   "tcp frame flattens CR and LF and ends with one newline");
            expect(no_break(buf, n, 1), "tcp frame has no embedded line break");
            close(accepted);
        }
        csyslog_close(&cfg);
        close(fd);
    }

    big = malloc(OS_CSYSLOG_MAX + 1);
    expect(big != NULL, "oversize buffer allocated");
    if (big != NULL) {
        fd = bind_loopback(SOCK_DGRAM, port, sizeof(port));
        expect(fd >= 0, "truncation socket bound");
        if (fd >= 0) {
            for (i = 0; i < OS_CSYSLOG_MAX; i++) {
                big[i] = 'A';
            }
            big[3] = '\r';
            big[OS_CSYSLOG_MAX - 1] = 'Z';
            fill_cfg(&cfg, CSYSLOG_UDP, port);
            expect(csyslog_send(&cfg, big, OS_CSYSLOG_MAX) == 0,
                   "oversize udp send succeeds");
            expect(recv_frame(fd, buf, sizeof(buf), &n) == 0,
                   "oversize udp datagram received");
            expect(n == (size_t)OS_CSYSLOG_MAX - 1 &&
                       buf[3] == ' ' && no_break(buf, n, 0),
                   "udp truncates at the syslog maximum and flattens what remains");
            csyslog_close(&cfg);
            close(fd);
        }
        free(big);
    }

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
