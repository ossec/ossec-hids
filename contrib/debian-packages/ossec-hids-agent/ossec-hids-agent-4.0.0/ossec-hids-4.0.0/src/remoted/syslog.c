/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

/* Prototypes */
static int OS_IPNotAllowed(const char *srcip);


/* Check if an IP is not allowed */
static int OS_IPNotAllowed(const char *srcip)
{
    if (logr.denyips != NULL) {
        if (OS_IPFoundList(srcip, logr.denyips)) {
            return (1);
        }
    }
    if (logr.allowips != NULL) {
        if (OS_IPFoundList(srcip, logr.allowips)) {
            return (0);
        }
    }

    /* If the IP is not allowed, it will be denied */
    return (1);
}

/* Handle syslog connections */
void HandleSyslog()
{
    char buffer[OS_SIZE_1024 + 2];
    char srcip[IPSIZE + 1];
    char *buffer_pt = NULL;
    ssize_t recv_b;
    struct sockaddr_storage peer_info;
    socklen_t peer_size;
    fd_set fdsave, fdwork;                      /* select() work areas */
    int fdmax;                                  /* max socket number + 1 */
    int sock;                                   /* active socket */

    /* Set peer size */
    peer_size = sizeof(peer_info);

    /* Initialize some variables */
    memset(buffer, '\0', OS_SIZE_1024 + 2);

    /* initialize select() save area */
    fdsave = logr.netinfo->fdset;
    fdmax  = logr.netinfo->fdmax;        /* value preset to max fd + 1 */

    /* Connect to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }

    /* Infinite loop */
    while (1) {
        /* process connections through select() for multiple sockets */
        fdwork = fdsave;
        if (select (fdmax, &fdwork, NULL, NULL, NULL) < 0) {
            ErrorExit("ERROR: Call to syslog select() failed, errno %d - %s",
                      errno, strerror (errno));
        }

        /* read through socket list for active socket */
        for (sock = 0; sock <= fdmax; sock++) {
            if (FD_ISSET (sock, &fdwork)) {

                /* Receive message */
                recv_b = recvfrom(sock, buffer, OS_SIZE_1024, 0,
                                  (struct sockaddr *)&peer_info, &peer_size);

                /* Nothing received */
                if (recv_b <= 0) {
                    continue;
                }

                /* Null-terminate the message */
                buffer[recv_b] = '\0';

                /* Remove newline */
                if (buffer[recv_b - 1] == '\n') {
                    buffer[recv_b - 1] = '\0';
                }

                /* Set the source IP */
                satop((struct sockaddr *) &peer_info, srcip, IPSIZE);
                srcip[IPSIZE] = '\0';

                /* Remove syslog header */
                if (buffer[0] == '<') {
                    buffer_pt = strchr(buffer + 1, '>');
                    if (buffer_pt) {
                        buffer_pt++;
                    } else {
                        buffer_pt = buffer;
                    }
                } else {
                    buffer_pt = buffer;
                }

                /* Check if IP is allowed here */
                if (OS_IPNotAllowed(srcip)) {
                    merror(DENYIP_WARN, ARGV0, srcip);
                    continue;
                }

                if (SendMSG(logr.m_queue, buffer_pt, srcip, SYSLOG_MQ) < 0) {
                    merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

                    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
                    }
                }
            } /* if socket active */
        } /* for() loop on sockets */
    } /* while(1) loop for messages */
}

