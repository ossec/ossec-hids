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

void exponential_backoff(int *current, int maxwait) {
    sleep(*current);

    *current *= 2;
    if (*current >= maxwait) {
        *current = maxwait;
    }
}

/* Start the Message Queue. type: WRITE||READ */
int StartMQ(const char *path, short int type)
{
    int rc = 0;
    int maxwait = 9;
    int current = 1;
    int last = FALSE;

    if (type == READ) {
        return (OS_BindUnixDomain(path, 0660, OS_MAXSTR + 512));
    }

    /* Continuously wait for socket to become available */
    while (File_DateofChange(path) < 0) {
        if (last == TRUE) {
            merror(QUEUE_ERROR, __local_name, path, "Queue not found");
            return (-1);
        }

        if (current >= maxwait) {
            last = TRUE;
        }

        exponential_backoff(&current, maxwait);
    }

    /* reset waits */
    maxwait = 3;
    current = 1;

    /* Continuously connect to UNIX domain */
    while ((rc = OS_ConnectUnixDomain(path, OS_MAXSTR + 256)) < 0) {
        if (current >= maxwait) {
            merror(QUEUE_ERROR, __local_name, path, strerror(errno));
            return (-1);
        }

        exponential_backoff(&current, maxwait);
    }

    debug1(MSG_SOCKET_SIZE, __local_name, OS_getsocketsize(rc));
    return (rc);
}

/* Send a message to the queue */
int SendMSG(int queue, const char *message, const char *locmsg, char loc)
{
    int __mq_rcode;
    char tmpstr[OS_MAXSTR + 1];
    int maxwait = 9;
    int current = 1;
    int last = FALSE;

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

    /* Continuously attempt to send message */
    while ((__mq_rcode = OS_SendUnix(queue, tmpstr, 0)) < 0) {
        /* Error on the socket */
        if (__mq_rcode == OS_SOCKTERR) {
            merror("%s: socketerr (not available).", __local_name);
            close(queue);
            return (-1);
        }

        if (last == TRUE) {
            merror("%s: socket busy giving up after waiting (%d) seconds", __local_name, current);
            close(queue);
            return (-1);
        }

        if (current >= maxwait) {
            last = TRUE;
        }

        if (current >= 5) {
            merror("%s: socket busy...", __local_name);
        }

        exponential_backoff(&current, maxwait);
    }

    return (0);
}

#endif /* !WIN32 */
