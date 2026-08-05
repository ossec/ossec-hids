/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "csyslogd.h"
#include "os_net/os_net.h"

/* Prototypes */
static void help_csyslogd(int status) __attribute__((noreturn));


/* Print help statement */
static void help_csyslogd(int status)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", MAILUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(status);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;

    /* Use MAILUSER (read only) */
    const char *dir  = DEFAULTDIR;
    const char *user = MAILUSER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Database Structure */
    SyslogConfig **syslog_config;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_csyslogd(0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_csyslogd(1);
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Read configuration */
    syslog_config = OS_ReadSyslogConf(test_config, cfg);

    /* Get server hostname */
    memset(__shost, '\0', 512);
    if (gethostname(__shost, 512 - 1) != 0) {
        ErrorExit("%s: ERROR: gethostname() failed", ARGV0);
    } else {
        /* Save the full hostname */
        memcpy(__shost_long, __shost, 512);

        char *ltmp;

        /* Remove domain part if available */
        ltmp = strchr(__shost, '.');
        if (ltmp) {
            *ltmp = '\0';
        }
    }

    /* Validate syslog_output servers. Hostnames are connected before chroot
     * below so OS_Connect() keeps multi-address / IPv4 fallback (#1744). */
    if (syslog_config) {
        unsigned int s = 0;

        while (syslog_config[s]) {
            int ip_check;

            if (!syslog_config[s]->server || syslog_config[s]->server[0] == '\0') {
                ErrorExit("%s: ERROR: syslog_output server is empty.", ARGV0);
            }

            /* OS_IsValidIP: 1 = host IP, 2 = IP/CIDR (not a valid syslog target). */
            ip_check = OS_IsValidIP(syslog_config[s]->server, NULL);
            if (ip_check == 2) {
                ErrorExit("%s: ERROR: syslog_output server '%s' must be a "
                          "hostname or IP address, not a network/CIDR.",
                          ARGV0, syslog_config[s]->server);
            }

            /* Under -t, probe hostname resolution without collapsing to one IP. */
            if (test_config && ip_check == 0) {
                char *probe = OS_GetHost(syslog_config[s]->server, 5);

                if (!probe || probe[0] == '\0') {
                    free(probe);
                    ErrorExit("%s: ERROR: Unable to resolve syslog_output server "
                              "hostname '%s'.", ARGV0, syslog_config[s]->server);
                }
                free(probe);
            }

            s++;
        }
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }

    /* Not configured */
    if (!syslog_config || !syslog_config[0]) {
        verbose("%s: INFO: Remote syslog server not configured. "
                "Clean exit.", ARGV0);
        exit(0);
    }

    /* Connect before chroot: DNS works here and OS_Connect* can walk the
     * full addrinfo list (IPv6 then IPv4 fallback). FDs survive chroot.
     * TLS loads CA paths here before the chroot jail. */
    {
        unsigned int s = 0;

        while (syslog_config[s]) {
            const char *proto = (syslog_config[s]->protocol == CSYSLOG_TCP) ?
                                "tcp" : "udp";
            const char *tls = syslog_config[s]->tls ? "+tls" : "";

            if (csyslog_connect(syslog_config[s]) < 0) {
                merror(CONNS_ERROR, ARGV0, syslog_config[s]->server);
            } else {
                /* Use merror for visibility at default log level (historical). */
                merror("%s: INFO: Forwarding alerts via syslog (%s%s) to: '%s:%s'.",
                       ARGV0, proto, tls,
                       syslog_config[s]->server, syslog_config[s]->port);
            }
            s++;
        }
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Now in chroot */
    nowChroot();

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Basic start up completed */
    debug1(CHROOT_MSG, ARGV0, dir);
    debug1(PRIVSEP_MSG, ARGV0, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* The real daemon now */
    OS_CSyslogD(syslog_config);
}

