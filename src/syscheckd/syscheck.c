/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Syscheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 */

#include "shared.h"
#include "syscheck.h"
#include "rootcheck/rootcheck.h"

/* Prototypes */
static void read_internal(int debug_level);
static void help_syscheckd(void) __attribute__((noreturn));

syscheck_config syscheck;

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_cookie = 0;


void init_magic(magic_t *cookie_ptr)
{
    if (!cookie_ptr || *cookie_ptr) {
        return;
    }

    *cookie_ptr = magic_open(MAGIC_MIME_TYPE);

    if (!*cookie_ptr) {
        const char *err = magic_error(*cookie_ptr);
        merror("%s: ERROR: Can't init libmagic: %s", ARGV0, err ? err : "unknown");
    } else if (magic_load(*cookie_ptr, NULL) < 0) {
        const char *err = magic_error(*cookie_ptr);
        merror("%s: ERROR: Can't load magic file: %s", ARGV0, err ? err : "unknown");
        magic_close(*cookie_ptr);
        *cookie_ptr = 0;
    }
}
#endif /* USE_MAGIC */

/* Read syscheck internal options */
static void read_internal(int debug_level)
{
    syscheck.tsleep = (unsigned int) getDefine_Int("syscheck", "sleep", 0, 64);
    syscheck.sleep_after = getDefine_Int("syscheck", "sleep_after", 1, 9999);

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        debug_level = getDefine_Int("syscheck", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    return;
}

/* Send a message to the monitor that we allow one change events on
   this file until timestamp
 */
static int allowChange(char* filename, time_t timestamp)
{
    char msg[OS_MAXPATH*2];
    sprintf(msg, "%ld %s", timestamp, filename);
    if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
    }
    if (SendMSG(syscheck.queue, msg, ALLOWCHANGE, ALLOWCHANGE_MQ) < 0) {
        merror(QUEUE_SEND, ARGV0);
    }
    debug1("%s: send_allowchange_msg: %s to %s\n", ARGV0, msg, DEFAULTQPATH);
    return 0;
}

#ifdef WIN32
/* syscheck main for Windows */
int Start_win32_Syscheck()
{
    int debug_level = 0;
    int r = 0;
    char *cfg = DEFAULTCPATH;

    /* Read internal options */
    read_internal(debug_level);

    debug1(STARTED_MSG, ARGV0);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        ErrorExit(NO_CONFIG, ARGV0, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        /* Disabled */
        if (!syscheck.dir) {
            merror(SK_NO_DIR, ARGV0);
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL);
        } else if (!syscheck.dir[0]) {
            merror(SK_NO_DIR, ARGV0);
        }
        syscheck.dir[0] = NULL;

        if (!syscheck.registry) {
            dump_syscheck_entry(&syscheck, "", 0, 1, NULL);
        }
        syscheck.registry[0] = NULL;

        merror("%s: WARN: Syscheck disabled.", ARGV0);
    }

    /* Rootcheck config */
    if (rootcheck_init(0) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
        merror("%s: WARN: Rootcheck module disabled.", ARGV0);
    }

    /* Print options */
    r = 0;
    while (syscheck.registry[r] != NULL) {
        verbose("%s: INFO: Monitoring registry entry: '%s'.",
                ARGV0, syscheck.registry[r]);
        r++;
    }

    /* Print directories to be monitored */
    r = 0;
    while (syscheck.dir[r] != NULL) {
	char optstr[ 100 ];
        verbose("%s: INFO: Monitoring directory: '%s', with options %s.",
	    ARGV0, syscheck.dir[r],
	    syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
        r++;
    }

    /* Print ignores. */
    if(syscheck.ignore)
	for (r = 0; syscheck.ignore[r] != NULL; r++)
	    verbose("%s: INFO: ignoring: '%s'",
		ARGV0, syscheck.ignore[r]);


    /* Print files with no diff. */
    if (syscheck.nodiff){
        r = 0;
        while (syscheck.nodiff[r] != NULL) {
            verbose("%s: INFO: No diff for file: '%s'",
                    ARGV0, syscheck.nodiff[r]);
            r++;
        }
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());

    /* Some sync time */
    sleep(syscheck.tsleep + 10);

    /* Wait if agent started properly */
    os_wait();

    start_daemon();

    exit(0);
}
#endif /* WIN32 */

/* Print help statement */
static void help_syscheckd()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-c config] [-a filename -u timestamp]", ARGV0);
    print_out("    -V             Version and license message");
    print_out("    -h             This help message");
    print_out("    -d             Execute in debug mode. This parameter");
    print_out("                   can be specified multiple times");
    print_out("                   to increase the debug level.");
    print_out("    -t             Test configuration");
    print_out("    -f             Run in foreground");
    print_out("    -c <config>    Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -a <filename>  Allow changes on filename");
    print_out("    -u <timestamp> Allow changes until timestamp");
    print_out(" ");
    exit(1);
}

#ifndef WIN32
/* Syscheck unix main */
int main(int argc, char **argv)
{
    int c, r;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;
    int allow_change = 0;
    const char *cfg = DEFAULTCPATH;
    char allow_filename[OS_MAXPATH];
    time_t allow_timestamp = 0;

    /* Set the name */
    OS_SetName(ARGV0);
    *allow_filename = '\0';

    while ((c = getopt(argc, argv, "Vtdhfc:a:u:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_syscheckd();
                break;
            case 'd':
                nowDebug();
                debug_level ++;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 'a':
                if (!optarg) {
                    ErrorExit("%s: -a needs a filename", ARGV0);
                }
                strncpy(allow_filename, optarg, OS_MAXPATH);
                allow_change = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -w needs a timestamp", ARGV0);
                }
                allow_timestamp = atoi(optarg);
                allow_change = 1;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_syscheckd();
                break;
        }
    }

    /* Read internal options */
    read_internal(debug_level);

    debug1(STARTED_MSG, ARGV0);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        ErrorExit(NO_CONFIG, ARGV0, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        if (!syscheck.dir) {
            if (!test_config) {
                merror(SK_NO_DIR, ARGV0);
            }
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL);
        } else if (!syscheck.dir[0]) {
            if (!test_config) {
                merror(SK_NO_DIR, ARGV0);
            }
        }
        syscheck.dir[0] = NULL;
        if (!test_config) {
            merror("%s: WARN: Syscheck disabled.", ARGV0);
        }
    }


    if (allow_change){
        if (allow_timestamp == 0){
            merror("%s: WARN: Missing timestamp for allow change", ARGV0);
            exit(1);
        } else if (*allow_filename != '\0') {
            allowChange(allow_filename, allow_timestamp);
            exit(0);
        } else {
            debug1("%s: Reading filenames from stdin, one path per line", ARGV0);
            while (fgets(allow_filename, OS_MAXPATH, stdin)) {
                /* Remove the newline character */
                if (allow_filename[strlen(allow_filename) - 1] == '\n') {
                    allow_filename[strlen(allow_filename) - 1] = '\0';
                }
                allowChange(allow_filename, allow_timestamp);
            }
            exit(0);
        }
    }

    /* Rootcheck config */
    if (rootcheck_init(test_config) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
        merror("%s: WARN: Rootcheck module disabled.", ARGV0);
    }

    /* Exit if testing config */
    if (test_config) {
        exit(0);
    }

    /* Setup libmagic */
#ifdef USE_MAGIC
    init_magic(&magic_cookie);
#endif

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Initial time to settle */
    sleep(syscheck.tsleep + 2);

    /* Connect to the queue */
    if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
        merror(QUEUE_ERROR, ARGV0, DEFAULTQPATH, strerror(errno));

        sleep(5);
        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            /* more 10 seconds of wait */
            merror(QUEUE_ERROR, ARGV0, DEFAULTQPATH, strerror(errno));
            sleep(10);
            if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }
        }
    }

    /* Start signal handling */
    StartSIG(ARGV0);

    /* Create pid */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    if (syscheck.rootcheck) {
        verbose(STARTUP_MSG, "ossec-rootcheck", (int)getpid());
    }

    /* Print directories to be monitored */
    r = 0;
    while (syscheck.dir[r] != NULL) {
	char optstr[ 100 ];
        verbose("%s: INFO: Monitoring directory: '%s', with options %s.",
	    ARGV0, syscheck.dir[r],
	    syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
        r++;
    }

    /* Print ignores. */
    if(syscheck.ignore)
	for (r = 0; syscheck.ignore[r] != NULL; r++)
	    verbose("%s: INFO: ignoring: '%s'",
		ARGV0, syscheck.ignore[r]);

    /* Print files with no diff. */
    if (syscheck.nodiff){
        r = 0;
        while (syscheck.nodiff[r] != NULL) {
            verbose("%s: INFO: No diff for file: '%s'",
                    ARGV0, syscheck.nodiff[r]);
            r++;
        }
    }

    /* Check directories set for real time */
    r = 0;
    while (syscheck.dir[r] != NULL) {
        if (syscheck.opts[r] & CHECK_REALTIME) {
#ifdef INOTIFY_ENABLED
            verbose("%s: INFO: Directory set for real time monitoring: "
                    "'%s'.", ARGV0, syscheck.dir[r]);
#elif defined(WIN32)
            verbose("%s: INFO: Directory set for real time monitoring: "
                    "'%s'.", ARGV0, syscheck.dir[r]);
#else
            verbose("%s: WARN: Ignoring flag for real time monitoring on "
                    "directory: '%s'.", ARGV0, syscheck.dir[r]);
#endif
        }
        r++;
    }

    /* Some sync time */
    sleep(syscheck.tsleep + 10);

    /* Start the daemon */
    start_daemon();
}

#endif /* !WIN32 */
