/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remoted.h"

typedef struct remoted_listener_arg {
    int position;
} remoted_listener_arg;

/* Prototypes */
static void help_remoted(int status) __attribute__((noreturn));
static void *remoted_listener_thread(void *arg);
static void remoted_HandleSIG(int sig);


/* Print help statement */
static void help_remoted(int status)
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
    print_out("    -u <user>   User to run as (default: %s)", REMUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(status);
}

static void remoted_HandleSIG(int sig)
{
    remoted_request_shutdown(sig);
}

static void *remoted_listener_thread(void *arg)
{
    remoted_listener_arg *la = (remoted_listener_arg *)arg;

    os_block_worker_signals();

    debug1("%s: DEBUG: Starting remoted listener: '%d'.", ARGV0, la->position);
    HandleRemote(la->position);
    free(la);
    return NULL;
}

int main(int argc, char **argv)
{
    int i = 0, c = 0;
    uid_t uid;
    gid_t gid;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;

    const char *cfg = DEFAULTCPATH;
    const char *dir = DEFAULTDIR;
    const char *user = REMUSER;
    const char *group = GROUPGLOBAL;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdthfu:g:c:D:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_remoted(0);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
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
            case 't':
                test_config = 1;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c need an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            default:
                help_remoted(1);
                break;
        }
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("remoted", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    debug1(STARTED_MSG, ARGV0);

    /* Return 0 if not configured */
    if (RemotedConfig(cfg, &logr) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Exit if test_config is set */
    if (test_config) {
        exit(0);
    }

    if (logr.conn == NULL) {
        /* Not configured */
        exit(0);
    }

    {
        int secure_count = 0;
        int j;

        for (j = 0; logr.conn[j] != 0; j++) {
            if (logr.conn[j] == SECURE_CONN) {
                secure_count++;
            }
        }
        if (secure_count > 1) {
            ErrorExit("%s: ERROR: Only one secure remoted connection is supported.",
                      ARGV0);
        }
    }

    /* Don't exit when client.keys empty (if set) */
    if (getDefine_Int("remoted", "pass_empty_keyfile", 0, 1)) {
        OS_PassEmptyKeyfile();
    }


    /* Check if the user and group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Setup random */
    srandom_init();

    /* pid before going daemon */
    i = getpid();

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Set new group */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }
    nowChroot();

    /* Start the signal manipulation */
    StartSIG2(ARGV0, remoted_HandleSIG);

    random();

    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* Bind all listeners before dropping UID (setuid is process-wide) */
    i = 0;
    while (logr.conn[i] != 0) {
        if (i >= REMOTE_LISTENERS_MAX) {
            ErrorExit("%s: ERROR: Too many remoted connections (max %d).",
                      ARGV0, REMOTE_LISTENERS_MAX);
        }
        remoted_bind_listener(i);
        i++;
    }

    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Start one thread per configured listener */
    i = 0;
    while (logr.conn[i] != 0) {
        remoted_listener_arg *la;

        os_calloc(1, sizeof(remoted_listener_arg), la);
        la->position = i;

        if (CreateThread(remoted_listener_thread, la) != 0) {
            free(la);
            ErrorExit(THREAD_ERROR, ARGV0);
        }
        i++;
    }

    while (1) {
        if (remoted_shutting_down) {
            remoted_wait_for_shutdown();
            exit(0);
        }
        sleep(1);
    }

    return (0);
}

