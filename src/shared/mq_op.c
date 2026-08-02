/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"


#ifndef WIN32

/* Table-driven retries preserve historical wait budgets while avoiding
 * nested sleep ladders (see PR #578 / @awiddersheim).
 */

/* Wait for the queue socket path to appear. Returns 0 if present, -1 if not.
 * delays[] are sleeps between existence checks (total wait 1+5+15 = 21s).
 */
static int mq_wait_for_path(const char *path, const unsigned int *delays, size_t ndelays)
{
    size_t i;

    if (File_DateofChange(path) >= 0) {
        return (0);
    }

    for (i = 0; i < ndelays; i++) {
        sleep(delays[i]);
        if (File_DateofChange(path) >= 0) {
            return (0);
        }
    }

    return (-1);
}

/* Start the Message Queue. type: WRITE||READ */
int StartMQ(const char *path, short int type)
{
    int rc;
    size_t i;
    static const unsigned int path_waits[] = { 1, 5, 15 };
    static const unsigned int connect_waits[] = { 1, 2 };

    if (type == READ) {
        return (OS_BindUnixDomain(path, 0660, OS_MAXSTR + 512));
    }

    /* Give the other end up to 21 seconds to create the socket. */
    if (mq_wait_for_path(path, path_waits,
                         sizeof(path_waits) / sizeof(path_waits[0])) < 0) {
        merror(QUEUE_ERROR, __local_name, path, "Queue not found");
        return (-1);
    }

    /* Up to 3 connect attempts with 1s then 2s between failures (~3s sleeps). */
    rc = OS_ConnectUnixDomain(path, OS_MAXSTR + 256);
    for (i = 0; rc < 0 && i < sizeof(connect_waits) / sizeof(connect_waits[0]); i++) {
        sleep(connect_waits[i]);
        rc = OS_ConnectUnixDomain(path, OS_MAXSTR + 256);
    }
    if (rc < 0) {
        merror(QUEUE_ERROR, __local_name, path, strerror(errno));
        return (-1);
    }

    debug1(MSG_SOCKET_SIZE, __local_name, OS_getsocketsize(rc));
    return (rc);
}

/* Send a message to the queue */
int SendMSG(int queue, const char *message, const char *locmsg, char loc)
{
    int __mq_rcode;
    char tmpstr[OS_MAXSTR + 1];
    size_t i;
    static const unsigned int send_waits[] = { 1, 3, 5, 10 };

    tmpstr[OS_MAXSTR] = '\0';

    /* Check for global locks */
    os_wait();

    if (loc == SECURE_MQ) {
        loc = message[0];
        message++;

        if (message[0] != ':') {
            merror(FORMAT_ERROR, __local_name);
            return (0);
        }
        message++; /* Pointing now to the location */

        if (strncmp(message, "keepalive", 9) == 0) {
            return (0);
        }

        snprintf(tmpstr, OS_MAXSTR, "%c:%s->%s", loc, locmsg, message);
    } else {
        snprintf(tmpstr, OS_MAXSTR, "%c:%s:%s", loc, locmsg, message);
    }

    /* Queue not available */
    if (queue < 0) {
        return (-1);
    }

    /* Five send attempts; after the first failure, sleep 1/3/5/10s
     * between retries (total sleep budget 19s). OS_SOCKTERR is fatal
     * only on the initial attempt, matching historical behavior.
     */
    __mq_rcode = OS_SendUnix(queue, tmpstr, 0);
    if (__mq_rcode < 0) {
        if (__mq_rcode == OS_SOCKTERR) {
            merror("%s: socketerr (not available).", __local_name);
            close(queue);
            return (-1);
        }

        for (i = 0; i < sizeof(send_waits) / sizeof(send_waits[0]); i++) {
            sleep(send_waits[i]);
            if (send_waits[i] >= 5) {
                merror("%s: socket busy ..", __local_name);
            }

            if (OS_SendUnix(queue, tmpstr, 0) >= 0) {
                return (0);
            }
        }

        /* Message is lost if the caller ignores the error. */
        close(queue);
        return (-1);
    }

    return (0);
}

#endif /* !WIN32 */
