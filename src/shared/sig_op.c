/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle signal manipulation */

#include <string.h>

#ifndef WIN32
#include <unistd.h>
#include <signal.h>
#endif

#include "sig_op.h"
#include "file_op.h"
#include "debug_op.h"
#include "error_messages/error_messages.h"

static const char *pidfile = NULL;

#ifndef WIN32
volatile sig_atomic_t sighup_received = 0;
#else
volatile int sighup_received = 0;
#endif

#ifndef WIN32
void HandleSIGHUP(__attribute__((unused)) int sig)
{
    sighup_received = 1;
}

void HandleSIG(int sig)
{
    const char *msg1 = "OSSEC: Received signal ";
    const char *msg2 = ". Exiting.\n";
    char sig_str[12];
    int i = 0;
    int n = sig;

    if (n < 0) {
        sig_str[i++] = '?';
    } else if (n == 0) {
        sig_str[i++] = '0';
    } else {
        char tmp[12];
        int j = 0;
        while (n > 0 && j < 11) {
            tmp[j++] = (n % 10) + '0';
            n /= 10;
        }
        while (j > 0) {
            sig_str[i++] = tmp[--j];
        }
    }
    sig_str[i] = '\0';

    write(STDERR_FILENO, msg1, sizeof("OSSEC: Received signal ") - 1);
    write(STDERR_FILENO, sig_str, i);
    write(STDERR_FILENO, msg2, sizeof(". Exiting.\n") - 1);

    /* DeletePID_AsyncSafe is strictly async-signal-safe as it only
     * calls unlink() on a pre-cached path.
     */
    DeletePID_AsyncSafe();
    _exit(1);
}


/* To avoid client-server communication problems */
void HandleSIGPIPE(__attribute__((unused)) int sig)
{
    return;
}

void StartSIG(const char *process_name)
{
    struct sigaction act;

    pidfile = process_name;

    memset(&act, 0, sizeof(act));
    act.sa_handler = HandleSIGHUP;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);

    memset(&act, 0, sizeof(act));
    act.sa_handler = HandleSIG;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    memset(&act, 0, sizeof(act));
    act.sa_handler = HandleSIGPIPE;
    sigaction(SIGPIPE, &act, NULL);
}

void StartSIG2(const char *process_name, void (*func)(int))
{
    struct sigaction act;

    pidfile = process_name;

    memset(&act, 0, sizeof(act));
    act.sa_handler = HandleSIGHUP;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);

    memset(&act, 0, sizeof(act));
    act.sa_handler = func;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    memset(&act, 0, sizeof(act));
    act.sa_handler = HandleSIGPIPE;
    sigaction(SIGPIPE, &act, NULL);
}

#endif /* !WIN32 */
