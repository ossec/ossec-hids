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
#include "headers/sec.h"


/* Start the agent daemon */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group)
{
    int rc = 0;
    int maxfd = 0;
    fd_set fdset;
    struct timeval fdtimeout;

    extern agent *agt;

    available_server = 0;

    /* Initial random numbers must happen before chroot */
    srandom_init();

    /* Going Daemon */
    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

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
    os_set_agent_crypto_method(&keys, agt->crypto_method);
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
    run_notify();

    /* Maxfd must be higher socket +1 */
    maxfd++;

    /* Monitor loop */
#ifndef WIN32
    sigset_t set, old_set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, &old_set);
#endif

    while (1) {
        if (sighup_received) {
            agent new_agt;
            char *old_server = NULL;
            char *old_port = NULL;
            int connect_id = 0;

            memset(&new_agt, 0, sizeof(agent));
            sighup_received = 0;
            merror("%s: INFO: SIGHUP received. Reloading configuration.", ARGV0);

            if (agt->rip && agt->rip[agt->rip_id]) {
                old_server = strdup(agt->rip[agt->rip_id]);
            }
            if (agt->port) {
                old_port = strdup(agt->port);
            }

            /* Copy current runtime state to temporary struct */
            new_agt.sock = agt->sock;
            new_agt.m_queue = agt->m_queue;

            if (ClientConf(cfgfile, &new_agt) < 0) {
                merror("%s: ERROR: Error reloading configuration (using old config)", ARGV0);
                FreeAgentConfig(&new_agt);
                free(old_server);
                free(old_port);
            } else {
                int reconnect = 0;

                /* Atomic swap */
                FreeAgentConfig(agt);
                memcpy(agt, &new_agt, sizeof(agent));

                if (agt->port == NULL) {
                    reconnect = 1;
                } else if (!old_port && agt->port) {
                    reconnect = 1;
                } else if (old_port && strcmp(old_port, agt->port) != 0) {
                    reconnect = 1;
                } else if (old_server && agt->rip && agt->rip[0]) {
                    if (!agent_address_in_rip(old_server)) {
                        reconnect = 1;
                    }
                } else if (agt->rip && agt->rip[0]) {
                    reconnect = 1;
                }

                if (reconnect && agt->allow_reload_reconnect) {
                    if (old_server) {
                        connect_id = agent_connect_id_for_address(old_server);
                    }
                }

                free(old_server);
                old_server = NULL;
                free(old_port);
                old_port = NULL;

                if (reconnect) {
                    if (agt->allow_reload_reconnect) {
                        merror("%s: INFO: Reload requires reconnecting to server (config changed).", ARGV0);
                        connect_server(connect_id);
                        start_agent(0);
                    } else {
                        merror("%s: WARNING: Server or port changed on reload but "
                               "<allow-reload-reconnect> is not enabled; keeping current connection.", ARGV0);
                    }
                }
            }
        }

        /* Monitor all available sockets from here */
        FD_ZERO(&fdset);
        FD_SET(agt->sock, &fdset);
        FD_SET(agt->m_queue, &fdset);

        fdtimeout.tv_sec = 1;
        fdtimeout.tv_usec = 0;

        /* Continuously send notifications */
        run_notify();

        /* Wait for the next socket message - unblock SIGHUP during wait */
#ifndef WIN32
        sigprocmask(SIG_SETMASK, &old_set, NULL);
#endif
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
#ifndef WIN32
        sigprocmask(SIG_BLOCK, &set, NULL);
#endif

        if (rc == -1) {
            if (errno == EINTR) {
                continue;
            }
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
            EventForward();
        }
    }
}

