/*
 * Regression for issue #1611: <local_ip> binds only that address.
 *
 *   make TARGET=server
 *   make -f tests/regressions/Makefile check
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "shared.h"
#include "os_net/os_net.h"

static void close_ni(OSNetInfo *ni)
{
    int i;

    if (!ni) {
        return;
    }

    if (ni->status >= 0) {
        for (i = 0; i < ni->fdcnt; i++) {
            OS_CloseSocket(ni->fds[i]);
        }
    }

    free(ni);
}

static int ipv6_loopback_ok(void)
{
    int fd;
    struct sockaddr_in6 sa;

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return (0);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_loopback;
    sa.sin6_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return (0);
    }

    close(fd);
    return (1);
}

static int sock_name(int fd, struct sockaddr_storage *ss)
{
    socklen_t len = sizeof(*ss);

    memset(ss, 0, sizeof(*ss));
    if (getsockname(fd, (struct sockaddr *)ss, &len) != 0) {
        fprintf(stderr, "FAIL: getsockname: %s\n", strerror(errno));
        return (-1);
    }

    return (0);
}

static unsigned short sock_port(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        return (ntohs(((const struct sockaddr_in *)ss)->sin_port));
    }
    if (ss->ss_family == AF_INET6) {
        return (ntohs(((const struct sockaddr_in6 *)ss)->sin6_port));
    }
    return (0);
}

static int addr_is(const struct sockaddr_storage *ss, int family, const char *expect)
{
    char buf[INET6_ADDRSTRLEN];

    if (ss->ss_family != family) {
        return (0);
    }

    memset(buf, 0, sizeof(buf));
    if (family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf, sizeof(buf));
    } else {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, buf, sizeof(buf));
    }

    return (strcmp(buf, expect) == 0);
}

static int udp_ready(int fd, int timeout_ms)
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return (select(fd + 1, &rfds, NULL, NULL, &tv));
}

static int send_udp(const char *ip, unsigned short port, const char *msg)
{
    int fd;
    int rc;
    char portstr[8];

    snprintf(portstr, sizeof(portstr), "%u", (unsigned int)port);
    fd = OS_ConnectUDP(portstr, ip);
    if (fd < 0) {
        return (-1);
    }

    rc = OS_SendUDPbySize(fd, (int)strlen(msg), msg);
    OS_CloseSocket(fd);
    return (rc);
}

static int test_local_ipv4(void)
{
    OSNetInfo *ni;
    struct sockaddr_storage ss;
    char buf[64];
    int n;

    ni = OS_Bindportudp("0", "127.0.0.1", OS_BIND_IPV6_DEFAULT);
    if (!ni || ni->status < 0 || ni->fdcnt != 1) {
        fprintf(stderr, "FAIL: bind 127.0.0.1\n");
        close_ni(ni);
        return (1);
    }

    if (sock_name(ni->fds[0], &ss) != 0) {
        close_ni(ni);
        return (1);
    }

    if (!addr_is(&ss, AF_INET, "127.0.0.1")) {
        fprintf(stderr, "FAIL: 127.0.0.1 bind is not AF_INET 127.0.0.1 (family %d)\n",
                (int)ss.ss_family);
        close_ni(ni);
        return (1);
    }

    if (send_udp("127.0.0.1", sock_port(&ss), "v4") != 0) {
        fprintf(stderr, "FAIL: send to 127.0.0.1\n");
        close_ni(ni);
        return (1);
    }

    if (udp_ready(ni->fds[0], 500) <= 0) {
        fprintf(stderr, "FAIL: no datagram on IPv4-only bind\n");
        close_ni(ni);
        return (1);
    }

    n = recv(ni->fds[0], buf, sizeof(buf) - 1, 0);
    if (n < 2 || strncmp(buf, "v4", 2) != 0) {
        fprintf(stderr, "FAIL: IPv4 payload\n");
        close_ni(ni);
        return (1);
    }

    if (ipv6_loopback_ok()) {
        if (send_udp("::1", sock_port(&ss), "v6") == 0) {
            if (udp_ready(ni->fds[0], 200) > 0) {
                fprintf(stderr, "FAIL: IPv4 local_ip accepted IPv6 traffic\n");
                close_ni(ni);
                return (1);
            }
        }
    }

    close_ni(ni);
    return (0);
}

static int test_local_ipv6(void)
{
    OSNetInfo *ni;
    struct sockaddr_storage ss;
    char buf[64];
    int n;

    if (!ipv6_loopback_ok()) {
        printf("SKIP: no IPv6 loopback for ::1 bind\n");
        return (0);
    }

    ni = OS_Bindportudp("0", "::1", OS_BIND_IPV6_DEFAULT);
    if (!ni || ni->status < 0 || ni->fdcnt != 1) {
        fprintf(stderr, "FAIL: bind ::1\n");
        close_ni(ni);
        return (1);
    }

    if (sock_name(ni->fds[0], &ss) != 0) {
        close_ni(ni);
        return (1);
    }

    if (!addr_is(&ss, AF_INET6, "::1")) {
        fprintf(stderr, "FAIL: ::1 bind is not AF_INET6 ::1 (family %d)\n",
                (int)ss.ss_family);
        close_ni(ni);
        return (1);
    }

    if (send_udp("::1", sock_port(&ss), "v6") != 0) {
        fprintf(stderr, "FAIL: send to ::1\n");
        close_ni(ni);
        return (1);
    }

    if (udp_ready(ni->fds[0], 500) <= 0) {
        fprintf(stderr, "FAIL: no datagram on IPv6-only bind\n");
        close_ni(ni);
        return (1);
    }

    n = recv(ni->fds[0], buf, sizeof(buf) - 1, 0);
    if (n < 2 || strncmp(buf, "v6", 2) != 0) {
        fprintf(stderr, "FAIL: IPv6 payload\n");
        close_ni(ni);
        return (1);
    }

    if (send_udp("127.0.0.1", sock_port(&ss), "v4") == 0) {
        if (udp_ready(ni->fds[0], 200) > 0) {
            fprintf(stderr, "FAIL: IPv6 local_ip accepted IPv4 traffic\n");
            close_ni(ni);
            return (1);
        }
    }

    close_ni(ni);
    return (0);
}

static int test_wildcard(void)
{
    OSNetInfo *ni;
    struct sockaddr_storage ss;
    char buf[64];
    int n;

    ni = OS_Bindportudp("0", NULL, OS_BIND_IPV6_DEFAULT);
    if (!ni || ni->status < 0 || ni->fdcnt < 1) {
        fprintf(stderr, "FAIL: wildcard bind\n");
        close_ni(ni);
        return (1);
    }

    if (sock_name(ni->fds[0], &ss) != 0) {
        close_ni(ni);
        return (1);
    }

    if (send_udp("127.0.0.1", sock_port(&ss), "v4") != 0) {
        fprintf(stderr, "FAIL: send IPv4 to wildcard\n");
        close_ni(ni);
        return (1);
    }

    if (udp_ready(ni->fds[0], 500) <= 0) {
        fprintf(stderr, "FAIL: wildcard did not accept IPv4\n");
        close_ni(ni);
        return (1);
    }

    n = recv(ni->fds[0], buf, sizeof(buf) - 1, 0);
    if (n < 2 || strncmp(buf, "v4", 2) != 0) {
        fprintf(stderr, "FAIL: wildcard IPv4 payload\n");
        close_ni(ni);
        return (1);
    }

    if (ipv6_loopback_ok()) {
        int i;
        int got = 0;

        if (send_udp("::1", sock_port(&ss), "v6") != 0) {
            fprintf(stderr, "FAIL: send IPv6 to wildcard\n");
            close_ni(ni);
            return (1);
        }

        for (i = 0; i < ni->fdcnt; i++) {
            if (udp_ready(ni->fds[i], 300) > 0) {
                n = recv(ni->fds[i], buf, sizeof(buf) - 1, 0);
                if (n >= 2 && strncmp(buf, "v6", 2) == 0) {
                    got = 1;
                    break;
                }
            }
        }

        if (!got) {
            fprintf(stderr, "FAIL: wildcard did not accept IPv6\n");
            close_ni(ni);
            return (1);
        }
    }

    close_ni(ni);
    return (0);
}

static int test_ipv6_no_wildcard(void)
{
    OSNetInfo *ni;
    struct sockaddr_storage ss;

    ni = OS_Bindportudp("0", NULL, OS_BIND_IPV6_NO);
    if (!ni || ni->status < 0 || ni->fdcnt != 1) {
        fprintf(stderr, "FAIL: ipv6=no wildcard bind\n");
        close_ni(ni);
        return (1);
    }

    if (sock_name(ni->fds[0], &ss) != 0) {
        close_ni(ni);
        return (1);
    }

    if (ss.ss_family != AF_INET) {
        fprintf(stderr, "FAIL: ipv6=no should bind AF_INET (family %d)\n",
                (int)ss.ss_family);
        close_ni(ni);
        return (1);
    }

    if (ipv6_loopback_ok()) {
        if (send_udp("::1", sock_port(&ss), "v6") == 0) {
            if (udp_ready(ni->fds[0], 200) > 0) {
                fprintf(stderr, "FAIL: ipv6=no accepted IPv6 traffic\n");
                close_ni(ni);
                return (1);
            }
        }
    }

    if (send_udp("127.0.0.1", sock_port(&ss), "v4") != 0) {
        fprintf(stderr, "FAIL: send IPv4 to ipv6=no wildcard\n");
        close_ni(ni);
        return (1);
    }

    if (udp_ready(ni->fds[0], 500) <= 0) {
        fprintf(stderr, "FAIL: ipv6=no wildcard did not accept IPv4\n");
        close_ni(ni);
        return (1);
    }

    close_ni(ni);
    return (0);
}

static int test_local_ip_ignores_ipv6(void)
{
    OSNetInfo *ni;
    struct sockaddr_storage ss;

    ni = OS_Bindportudp("0", "127.0.0.1", OS_BIND_IPV6_YES);
    if (!ni || ni->status < 0 || ni->fdcnt != 1) {
        fprintf(stderr, "FAIL: local_ip with ipv6=yes\n");
        close_ni(ni);
        return (1);
    }

    if (sock_name(ni->fds[0], &ss) != 0) {
        close_ni(ni);
        return (1);
    }

    if (!addr_is(&ss, AF_INET, "127.0.0.1")) {
        fprintf(stderr, "FAIL: ipv6=yes must not override IPv4 local_ip\n");
        close_ni(ni);
        return (1);
    }

    close_ni(ni);

    if (!ipv6_loopback_ok()) {
        return (0);
    }

    ni = OS_Bindportudp("0", "::1", OS_BIND_IPV6_NO);
    if (!ni || ni->status < 0 || ni->fdcnt != 1) {
        fprintf(stderr, "FAIL: local_ip with ipv6=no\n");
        close_ni(ni);
        return (1);
    }

    if (sock_name(ni->fds[0], &ss) != 0) {
        close_ni(ni);
        return (1);
    }

    if (!addr_is(&ss, AF_INET6, "::1")) {
        fprintf(stderr, "FAIL: ipv6=no must not override IPv6 local_ip\n");
        close_ni(ni);
        return (1);
    }

    close_ni(ni);
    return (0);
}

int main(void)
{
    int failed = 0;

    failed |= test_local_ipv4();
    failed |= test_local_ipv6();
    failed |= test_wildcard();
    failed |= test_ipv6_no_wildcard();
    failed |= test_local_ip_ignores_ipv6();

    if (failed) {
        return (1);
    }

    printf("PASS: issue #1611 local_ip bind family\n");
    return (0);
}
