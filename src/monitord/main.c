/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config/config.h"
#include "monitord.h"
#include "os_net/os_net.h"
#ifdef USE_SMTP_CURL
#include <curl/curl.h>
#endif

/* Prototypes */
static void help_monitord(int status) __attribute__((noreturn));

#ifdef USE_SMTP_CURL
static void mond_clear_smtp_secrets(void)
{
    if (mond.smtp_user) {
        memset_secure(mond.smtp_user, 0, strlen(mond.smtp_user));
    }
    if (mond.smtp_pass) {
        memset_secure(mond.smtp_pass, 0, strlen(mond.smtp_pass));
    }
    if (mond.smtpserver_resolved) {
        free(mond.smtpserver_resolved);
        mond.smtpserver_resolved = NULL;
    }
    curl_global_cleanup();
}
#endif


/* Print help statement */
static void help_monitord(int status)
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
    print_out("    -u <user>   User to run as (default: %s)", USER);
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
    const char *dir  = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Initialize global variables */
    mond.a_queue = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_monitord(0);
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
                help_monitord(1);
                break;
        }

    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Get config options */
    mond.day_wait = (unsigned short) getDefine_Int("monitord", "day_wait", 5, 240);
    mond.compress = (short) getDefine_Int("monitord", "compress", 0, 1);
    mond.sign = (short) getDefine_Int("monitord", "sign", 0, 1);
    mond.monitor_agents = (short) getDefine_Int("monitord", "monitor_agents", 0, 1);
    mond.notify_time = getDefine_Int("monitord", "notify_time", 60, 3600);
    mond.agents = NULL;
    mond.smtpserver = NULL;
    mond.smtpserver_resolved = NULL;
    mond.emailfrom = NULL;
    mond.emailidsname = NULL;

    mond.authsmtp = 0;
    mond.securesmtp = 0;
    mond.smtp_port = 0;
    mond.smtp_user = NULL;
    mond.smtp_pass = NULL;

    c = 0;
    c |= CREPORTS;
    if (ReadConfig(c, cfg, &mond, NULL) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* If we have any reports configured, read smtp/emailfrom */
    if (mond.reports) {
        OS_XML xml;
        char *tmpsmtp;

        const char *(xml_smtp[]) = {"ossec_config", "global", "smtp_server", NULL};
        const char *(xml_from[]) = {"ossec_config", "global", "email_from", NULL};
        const char *(xml_idsname[]) = {"ossec_config", "global", "email_idsname", NULL};
        const char *(xml_auth_smtp[]) = {"ossec_config", "global", "auth_smtp", NULL};
        const char *(xml_secure_smtp[]) = {"ossec_config", "global", "secure_smtp", NULL};
        const char *(xml_smtp_port[]) = {"ossec_config", "global", "smtp_port", NULL};
        const char *(xml_smtp_user[]) = {"ossec_config", "global", "smtp_user", NULL};
        const char *(xml_smtp_pass[]) = {"ossec_config", "global", "smtp_password", NULL};

        if (OS_ReadXML(cfg, &xml) < 0) {
            ErrorExit(CONFIG_ERROR, ARGV0, cfg);
        }

#ifdef USE_SMTP_CURL
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            ErrorExit("%s: curl_global_init failed.", ARGV0);
        }
        atexit(mond_clear_smtp_secrets);
#endif

        tmpsmtp = OS_GetOneContentforElement(&xml, xml_smtp);
        mond.emailfrom = OS_GetOneContentforElement(&xml, xml_from);
        mond.emailidsname = OS_GetOneContentforElement(&xml, xml_idsname);

        if (tmpsmtp && mond.emailfrom) {
#ifdef USE_SMTP_CURL
            /* For libcurl builds, we store the original hostname and the resolved IP.
             * DNS resolution is required prior to chroot.
             */
            if (tmpsmtp[0] != '/') {
                mond.smtpserver_resolved = OS_GetHost(tmpsmtp, 5);
                if (!mond.smtpserver_resolved) {
                    mond.smtpserver = NULL;
                } else {
                    os_strdup(tmpsmtp, mond.smtpserver);
                }
            } else {
                os_strdup(tmpsmtp, mond.smtpserver);
            }
#else
            mond.smtpserver = OS_GetHost(tmpsmtp, 5);
#endif
            if (!mond.smtpserver) {
                merror(INVALID_SMTP, ARGV0, tmpsmtp);
                if (mond.emailfrom) {
                    free(mond.emailfrom);
                }
                mond.emailfrom = NULL;
                merror("%s: Invalid SMTP server.  Disabling email reports.", ARGV0);
            } else {
                /* Read SMTP auth config if available */
                char *tmp_auth = OS_GetOneContentforElement(&xml, xml_auth_smtp);
                if (tmp_auth) {
                    if (strcmp(tmp_auth, "yes") == 0) {
                        mond.authsmtp = 1;
                    } else if (strcmp(tmp_auth, "no") == 0) {
                        mond.authsmtp = 0;
                    } else {
                        merror("%s: ERROR: Invalid value for 'auth_smtp' (expected yes/no). Disabling email reports.", ARGV0);
                        mond.reports = NULL;
                    }
                    free(tmp_auth);
                }

                if (mond.reports) {
                    char *tmp_secure = OS_GetOneContentforElement(&xml, xml_secure_smtp);
                    if (tmp_secure) {
                        if (strcmp(tmp_secure, "yes") == 0) {
                            mond.securesmtp = 1;
                        } else if (strcmp(tmp_secure, "no") == 0) {
                            mond.securesmtp = 0;
                        } else {
                            merror("%s: ERROR: Invalid value for 'secure_smtp' (expected yes/no). Disabling email reports.", ARGV0);
                            mond.reports = NULL;
                        }
                        free(tmp_secure);
                    }
                }

                if (mond.reports) {
                    char *tmp_port = OS_GetOneContentforElement(&xml, xml_smtp_port);
                    if (tmp_port) {
                        if (OS_StrIsNum(tmp_port)) {
                            int p = atoi(tmp_port);
                            if (p > 0 && p <= 65535) {
                                mond.smtp_port = p;
                            } else {
                                merror("%s: ERROR: Invalid SMTP port '%s' (out of range 1-65535). Disabling email reports.", ARGV0, tmp_port);
                                mond.reports = NULL;
                            }
                        } else {
                            merror("%s: ERROR: Invalid SMTP port '%s' (not a number). Disabling email reports.", ARGV0, tmp_port);
                            mond.reports = NULL;
                        }
                        free(tmp_port);
                    }
                }

                if (mond.reports) {
                    mond.smtp_user = OS_GetOneContentforElement(&xml, xml_smtp_user);
                    mond.smtp_pass = OS_GetOneContentforElement(&xml, xml_smtp_pass);

                    if (mond.authsmtp && (!mond.smtp_user || !mond.smtp_pass)) {
                        merror("%s: ERROR: SMTP auth enabled but user/pass missing. Disabling email reports.", ARGV0);
                        if (mond.emailfrom) {
                            free(mond.emailfrom);
                            mond.emailfrom = NULL;
                        }
                        mond.reports = NULL;
                    }
                }
            }
            free(tmpsmtp);
            tmpsmtp = NULL;
        } else {
            if (tmpsmtp) {
                free(tmpsmtp);
            }
            if (mond.emailfrom) {
                free(mond.emailfrom);
            }

            mond.emailfrom = NULL;
            merror("%s: SMTP server or 'email from' missing. Disabling email reports.", ARGV0);
        }

        OS_ClearXML(&xml);
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

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    nowChroot();

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

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
    Monitord();
    exit(0);
}
