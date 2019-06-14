/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

#ifndef WIN32
#include "os_dns/os_dns.h"
#endif //WIN32

/* Start the agent daemon */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group)
{
    int rc = 0;
    int maxfd = 0;
    fd_set fdset;
    struct timeval fdtimeout;

    available_server = 0;

    /* Initial random numbers must happen before chroot */
    srandom_init();

    merror("going daemon");
    /* Going Daemon */
    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

#ifndef WIN32
    merror("starting imsg stuff");
    /* Prepare for os_dns */
    struct imsgbuf osdns_ibuf;
    extern struct imsgbuf server_ibuf;
    //struct imsgbuf osdns_ibuf;
    int imsg_fds[2];
    merror("Creating socketpair()");
    if ((socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds)) == -1) {
        ErrorExit("%s: ERROR: Could not create socket pair.", ARGV0);
    }
    if (setnonblock(imsg_fds[0]) < 0) {
        ErrorExit("%s: ERROR: Could not set imsg_fds[0] to nonblock", ARGV0);
    }
    if (setnonblock(imsg_fds[1]) < 0) {
        ErrorExit("%s: ERROR: Could not set imsg_fds[1] to nonblock", ARGV0);
    }

    /* Fork os_dns process */
    switch(fork()) {
        case -1:
            ErrorExit("%s: ERROR: Cannot fork() os_dns process", ARGV0);
        case 0:
            close(imsg_fds[0]);
	    merror("os_dns imsg_init()");
            imsg_init(&osdns_ibuf, imsg_fds[1]);
            exit(osdns(&osdns_ibuf, ARGV0));
    }

    /* Setup imsg for the rest of agentd */
    close(imsg_fds[1]);
    //imsg_init(&agt->ibuf, imsg_fds[1]);
    merror("agentd imsg_init()");
    imsg_init(&server_ibuf, imsg_fds[0]);

#endif  //WIN32

    /* Set group ID */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }
    nowChroot();

    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Create the queue and read from it. Exit if fails. */
    if ((agt->m_queue = StartMQ(DEFAULTQUEUE, READ)) < 0) {
        ErrorExit(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));
    }

    maxfd = agt->m_queue;
    agt->sock = -1;

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror(PID_ERROR, ARGV0);
    }

    /* Read private keys  */
    verbose(ENC_READ, ARGV0);

    OS_ReadKeys(&keys);
    OS_StartCounter(&keys);

    os_write_agent_info(keys.keyentries[0]->name, NULL, keys.keyentries[0]->id,
                        agt->profile);

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    random();

    /* Connect UDP */
    rc = 0;
    while (rc < agt->rip_id) {
        verbose("%s: INFO: Server %d: %s", ARGV0, rc+1, agt->rip[rc]);
        rc++;
    }

    /* Try to connect to the server */
    if (!connect_server(0)) {
        ErrorExit(UNABLE_CONN, ARGV0);
    }

    /* Set max fd for select */
    if (agt->sock > maxfd) {
        maxfd = agt->sock;
    }

    /* Connect to the execd queue */
    if (agt->execdq == 0) {
        if ((agt->execdq = StartMQ(EXECQUEUE, WRITE)) < 0) {
            merror("%s: INFO: Unable to connect to the active response "
                   "queue (disabled).", ARGV0);
            agt->execdq = -1;
        }
    }

    /* Try to connect to server */
    os_setwait();

    start_agent(1);

    os_delwait();

    /* Send integrity message for agent configs */
    intcheck_file(OSSECCONF, dir);
    intcheck_file(OSSEC_DEFINES, dir);

    /* Send first notification */
#ifdef WIN32
    run_notify();
#else
    run_notify();
#endif //WIN32

    /* Maxfd must be higher socket +1 */
    maxfd++;

    /* Monitor loop */
    while (1) {
        /* Monitor all available sockets from here */
        FD_ZERO(&fdset);
        FD_SET(agt->sock, &fdset);
        FD_SET(agt->m_queue, &fdset);

        fdtimeout.tv_sec = 1;
        fdtimeout.tv_usec = 0;

        /* Continuously send notifications */
#ifdef WIN32
        run_notify();
#else
        run_notify();
#endif //WIN32

        /* Wait with a timeout for any descriptor */
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        if (rc == -1) {
            ErrorExit(SELECT_ERROR, ARGV0, errno, strerror(errno));
        } else if (rc == 0) {
            continue;
        }

        /* For the receiver */
        if (FD_ISSET(agt->sock, &fdset)) {
            receive_msg();
        }

        /* For the forwarder */
        if (FD_ISSET(agt->m_queue, &fdset)) {
#ifdef WIN32
            EventForward();
#else
            EventForward();
#endif
        }
    }
}

