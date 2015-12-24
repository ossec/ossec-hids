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


/* Attempt to connect to all configured servers */
int connect_server(int initial_id)
{
    unsigned int attempts = 2;
    int rc = initial_id;

    /* Checking if the initial is zero, meaning we have to
     * rotate to the beginning
     */
    if (agt->rip[initial_id] == NULL) {
        rc = 0;
    }

    /* Close socket if available */
    if (agt->sock >= 0) {
        sleep(1);
        CloseSocket(agt->sock);
        agt->sock = -1;

        if (agt->rip[1]) {
            verbose("%s: INFO: Closing connection to server %s, port %s.",
                    ARGV0,
                    agt->rip[rc],
                    agt->port);
        }

    }

    while (agt->rip[rc]) {

        /* Connect to any useable address of the server */
        verbose("%s: INFO: Trying to connect to server %s, port %s.", ARGV0,
                agt->rip[rc],
                agt->port);

        agt->sock = OS_ConnectUDP(agt->port, agt->rip[rc]);

        if (agt->sock < 0) {
            agt->sock = -1;
            merror(CONNS_ERROR, ARGV0, agt->rip[rc]);
            rc++;

            if (agt->rip[rc] == NULL) {
                attempts += 10;

                /* Only log that if we have more than 1 server configured */
                if (agt->rip[1]) {
                    merror("%s: ERROR: Unable to connect to any server.", ARGV0);
                }

                sleep(attempts);
                rc = 0;
            }
        } else {
#ifdef HPUX
            /* Set socket non-blocking on HPUX */
            // fcntl(agt->sock, O_NONBLOCK);
#endif

#ifdef WIN32
            int bmode = 1;

            /* Set socket to non-blocking */
            ioctlsocket(agt->sock, FIONBIO, (u_long FAR *) &bmode);
#endif

            agt->rip_id = rc;
            return (1);
        }
    }

    return (0);
}

/* Send synchronization message to the server and wait for the ack */
void start_agent(int is_startup)
{
    ssize_t recv_b = 0;
    unsigned int attempts = 0, g_attempts = 1;

    char *tmp_msg;
    char msg[OS_MAXSTR + 2];
    char buffer[OS_MAXSTR + 1];
    char cleartext[OS_MAXSTR + 1];
    char fmsg[OS_MAXSTR + 1];

    memset(msg, '\0', OS_MAXSTR + 2);
    memset(buffer, '\0', OS_MAXSTR + 1);
    memset(cleartext, '\0', OS_MAXSTR + 1);
    memset(fmsg, '\0', OS_MAXSTR + 1);
    snprintf(msg, OS_MAXSTR, "%s%s", CONTROL_HEADER, HC_STARTUP);

#ifdef ONEWAY_ENABLED
    return;
#endif

    while (1) {
        /* Send start up message */
        send_msg(0, msg);
        attempts = 0;

        /* Read until our reply comes back */
        while (((recv_b = recv(agt->sock, buffer, OS_MAXSTR,
                               MSG_DONTWAIT)) >= 0) || (attempts <= 5)) {
            if (recv_b <= 0) {
                /* Sleep five seconds before trying to get the reply from
                 * the server again
                 */
                attempts++;
                sleep(attempts);

                /* Send message again (after three attempts) */
                if (attempts >= 3) {
                    send_msg(0, msg);
                }

                continue;
            }

            /* Id of zero -- only one key allowed */
            tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1);
            if (tmp_msg == NULL) {
                merror(MSG_ERROR, ARGV0, agt->rip[agt->rip_id]);
                continue;
            }

            /* Check for commands */
            if (IsValidHeader(tmp_msg)) {
                /* If it is an ack reply */
                if (strcmp(tmp_msg, HC_ACK) == 0) {
                    available_server = time(0);

                    verbose(AG_CONNECTED, ARGV0, agt->rip[agt->rip_id],
                            agt->port);

                    if (is_startup) {
                        /* Send log message about start up */
                        snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
                                 keys.keyentries[0]->name,
                                 keys.keyentries[0]->ip->ip);
                        snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
                                 "ossec", msg);
                        send_msg(0, fmsg);
                    }
                    return;
                }
            }
        }

        /* Wait for server reply */
        merror(AG_WAIT_SERVER, ARGV0, agt->rip[agt->rip_id]);

        /* If we have more than one server, try all */
        if (agt->rip[1]) {
            int curr_rip = agt->rip_id;
            merror("%s: INFO: Trying next server in the line: '%s'.", ARGV0,
                   agt->rip[agt->rip_id + 1] != NULL ? agt->rip[agt->rip_id + 1] : agt->rip[0]);
            connect_server(agt->rip_id + 1);

            if (agt->rip_id == curr_rip) {
                sleep(g_attempts);
                g_attempts += (attempts * 3);
            } else {
                g_attempts += 5;
                sleep(g_attempts);
            }
        } else {
            sleep(g_attempts);
            g_attempts += (attempts * 3);

            connect_server(0);
        }
    }

    return;
}

