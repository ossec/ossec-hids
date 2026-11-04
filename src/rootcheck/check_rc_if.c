/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef SOLARIS
#include <stropts.h>
#include <sys/sockio.h>
#endif

#include "headers/debug_op.h"
#include "headers/defs.h"
#include "rootcheck.h"

#ifndef IFCONFIG
#define IFCONFIG "ifconfig %s | grep PROMISC > /dev/null 2>&1"
#endif

/* Prototypes */
static int run_ifconfig(const char *ifconfig);

/* The name is not trusted: whoever may configure the network chooses it
 * and the kernel accepts shell metacharacters in interface names and
 * alias labels. It must reach the shell as one quoted word, and ifconfig
 * must not take it for an option (ANT-2026-9UQVLIX8).
 */
int rk_shell_quote_ifname(const char *ifname, char *out, size_t out_sz)
{
    size_t n = 0;

    if (ifname == NULL || out == NULL || out_sz < 3) {
        return (0);
    }
    if (*ifname == '\0' || *ifname == '-') {
        return (0);
    }

    /* Nothing is special between single quotes but the quote itself */
    out[n++] = '\'';
    for (; *ifname != '\0'; ifname++) {
        /* Room for an escaped quote, the closing quote and the NUL */
        if (n + 6 > out_sz) {
            return (0);
        }
        if (*ifname == '\'') {
            memcpy(out + n, "'\\''", 4);
            n += 4;
        } else {
            out[n++] = *ifname;
        }
    }
    out[n++] = '\'';
    out[n] = '\0';
    return (1);
}

/* Execute the ifconfig command
 * Returns 1 if the interface is in promiscuous mode
 */
static int run_ifconfig(const char *ifconfig)
{
    char nt[OS_SIZE_1024 + 1];
    char name[(IFNAMSIZ * 4) + 3];

    if (rk_shell_quote_ifname(ifconfig, name, sizeof(name)) != 1) {
        return (0);
    }

    snprintf(nt, OS_SIZE_1024, IFCONFIG, name);
    if (system(nt) == 0) {
        return (1);
    }

    return (0);
}

/* Check all interfaces for promiscuous mode */
void check_rc_if()
{
    int _fd, _errors = 0, _total = 0;
    struct ifreq tmp_str[16];

    struct ifconf _if;
    struct ifreq *_ir;
    struct ifreq *_ifend;
    struct ifreq _ifr;

    _fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (_fd < 0) {
        merror("%s: Error checking interfaces (socket)", ARGV0);
        return;
    }

    memset(tmp_str, 0, sizeof(struct ifreq) * 16);
    _if.ifc_len = sizeof(tmp_str);
    _if.ifc_buf = (caddr_t)(tmp_str);

    if (ioctl(_fd, SIOCGIFCONF, &_if) < 0) {
        close(_fd);
        merror("%s: Error checking interfaces (ioctl)", ARGV0);
        return;
    }

    _ifend = (struct ifreq *) (void *) ((char *)tmp_str + _if.ifc_len);
    _ir = tmp_str;

    /* Loop over all interfaces */
    for (; _ir < _ifend; _ir++) {
        strncpy(_ifr.ifr_name, _ir->ifr_name, sizeof(_ifr.ifr_name));

        /* Get information from each interface */
        if (ioctl(_fd, SIOCGIFFLAGS, (char *)&_ifr) == -1) {
            continue;
        }

        _total++;

        if ((_ifr.ifr_flags & IFF_PROMISC) ) {
            char op_msg[OS_SIZE_1024 + 1];
            if (run_ifconfig(_ifr.ifr_name)) {
                snprintf(op_msg, OS_SIZE_1024, "Interface '%s' in promiscuous"
                         " mode.", _ifr.ifr_name);
                notify_rk(ALERT_SYSTEM_CRIT, op_msg);
            } else {
                snprintf(op_msg, OS_SIZE_1024, "Interface '%s' in promiscuous"
                         " mode, but ifconfig is not showing it"
                         "(probably trojaned).", _ifr.ifr_name);
                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
            _errors++;
        }
    }
    close(_fd);

    if (_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "No problem detected on ifconfig/ifs."
                 " Analyzed %d interfaces.", _total);
        notify_rk(ALERT_OK, op_msg);
    }

    return;
}

#else /* WIN32 */

/* Not implemented on Windows */
void check_rc_if()
{
    return;
}

#endif /* WIN32 */

