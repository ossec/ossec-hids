/*
 * Wildcard binds must not rely on AI_ADDRCONFIG.
 *
 * glibc getaddrinfo(3): with AI_ADDRCONFIG, loopback is not a "configured"
 * address. On loopback-only / early-boot / many container hosts,
 * getaddrinfo(NULL, port, AI_PASSIVE|AI_ADDRCONFIG) returns EAI_NONAME, so
 * remoted/authd with <ipv6>no</ipv6> and no <local_ip> never bind.
 *
 *   make TARGET=server
 *   make -f tests/regressions/Makefile issue_addrconfig_wildcard_bind
 *   ./issue_addrconfig_wildcard_bind
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
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

    if (ni->status >= 0 || ni->fdcnt > 0) {
        for (i = 0; i < ni->fdcnt; i++) {
            OS_CloseSocket(ni->fds[i]);
        }
    }

    free(ni);
}

/* 1 if AI_PASSIVE|AI_ADDRCONFIG fails while AI_PASSIVE alone succeeds. */
static int loopback_only_addrconfig_trap(void)
{
    struct addrinfo hints, *res = NULL;
    int with_cfg;
    int passive_only;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    with_cfg = getaddrinfo(NULL, "0", &hints, &res);
    if (res) {
        freeaddrinfo(res);
        res = NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    passive_only = getaddrinfo(NULL, "0", &hints, &res);
    if (res) {
        freeaddrinfo(res);
    }

    return (with_cfg != 0 && passive_only == 0);
}

static OSNetInfo *bind_ipv6_no_wildcard(unsigned short *port_out)
{
    char portstr[8];
    int port;
    OSNetInfo *ni;

    *port_out = 0;
    for (port = 20000; port < 21000; port++) {
        snprintf(portstr, sizeof(portstr), "%d", port);
        ni = OS_Bindportudp(portstr, NULL, OS_BIND_IPV6_NO);
        if (ni && ni->status >= 0 && ni->fdcnt >= 1) {
            *port_out = (unsigned short)port;
            return (ni);
        }
        close_ni(ni);
    }
    return (NULL);
}

static int test_ipv6_no_wildcard_bind(void)
{
    OSNetInfo *ni;
    struct sockaddr_storage ss;
    socklen_t slen;
    unsigned short port;

    ni = bind_ipv6_no_wildcard(&port);
    if (!ni) {
        fprintf(stderr, "FAIL: ipv6=no wildcard OS_Bindportudp%s\n",
                loopback_only_addrconfig_trap()
                ? " — AI_ADDRCONFIG loopback trap is active on this host"
                : "");
        return (1);
    }

    slen = sizeof(ss);
    if (getsockname(ni->fds[0], (struct sockaddr *)&ss, &slen) != 0) {
        fprintf(stderr, "FAIL: getsockname: %s\n", strerror(errno));
        close_ni(ni);
        return (1);
    }

    if (ss.ss_family != AF_INET) {
        fprintf(stderr, "FAIL: expected AF_INET wildcard, got family %d\n",
                (int)ss.ss_family);
        close_ni(ni);
        return (1);
    }

    close_ni(ni);
    return (0);
}

int main(void)
{
    if (loopback_only_addrconfig_trap()) {
        printf("INFO: this host hits the AI_ADDRCONFIG loopback trap; "
               "OS_Bindport must still succeed\n");
    }

    if (test_ipv6_no_wildcard_bind() != 0) {
        return (1);
    }

    printf("PASS: AI_ADDRCONFIG-free ipv6=no wildcard bind\n");
    return (0);
}
