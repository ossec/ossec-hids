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


/* Checks if an IP is not allowed */
static int OS_IPNotAllowed(char *srcip)
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

/* Handle each client */
static void HandleClient(int client_socket, char *srcip)
{
    int sb_size = OS_MAXSTR;
    int r_sz = 0;

    char buffer[OS_MAXSTR + 2];
    char storage_buffer[OS_MAXSTR + 2];
    char tmp_buffer[OS_MAXSTR + 2];

    char *buffer_pt = NULL;

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Initialize some variables */
    memset(buffer, '\0', OS_MAXSTR + 2);
    memset(storage_buffer, '\0', OS_MAXSTR + 2);
    memset(tmp_buffer, '\0', OS_MAXSTR + 2);


    while (1) {
        /* If we fail, we need to return and close the socket */
        if ((r_sz = OS_RecvTCPBuffer(client_socket, buffer, OS_MAXSTR - 2)) < 0) {
            close(client_socket);
            DeletePID(ARGV0);
            return;
        }

        /* We must have a new line at the end */
        buffer_pt = strchr(buffer, '\n');
        if (!buffer_pt) {
            /* Buffer is full */
            if ((sb_size - r_sz) <= 2) {
                merror("%s: Full buffer receiving from: '%s'", ARGV0, srcip);
                sb_size = OS_MAXSTR;
                storage_buffer[0] = '\0';
                continue;
            }

            strncat(storage_buffer, buffer, sb_size);
            sb_size -= r_sz;
            continue;
        }

        /* See if we received more than just one message */
        if (*(buffer_pt + 1) != '\0') {
            *buffer_pt = '\0';
            buffer_pt++;
            strncpy(tmp_buffer, buffer_pt, OS_MAXSTR);
        }

        /* Store everything in the storage_buffer
         * Check if buffer will be full
         */
        if ((sb_size - r_sz) <= 2) {
            merror("%s: Full buffer receiving from: '%s'.", ARGV0, srcip);
            sb_size = OS_MAXSTR;
            storage_buffer[0] = '\0';
            tmp_buffer[0] = '\0';
            continue;
        }

        strncat(storage_buffer, buffer, sb_size);

        /* Remove carriage returns too */
        buffer_pt = strchr(storage_buffer, '\r');
        if (buffer_pt) {
            *buffer_pt = '\0';
        }

        /* Remove syslog header */
        if (storage_buffer[0] == '<') {
            buffer_pt = strchr(storage_buffer + 1, '>');
            if (buffer_pt) {
                buffer_pt++;
            } else {
                buffer_pt = storage_buffer;
            }
        } else {
            buffer_pt = storage_buffer;
        }

        /* Send to the queue */
        if (SendMSG(logr.m_queue, buffer_pt, srcip, SYSLOG_MQ) < 0) {
            merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

            if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
            }
        }

        /* Clean up the buffers */
        if (tmp_buffer[0] != '\0') {
            strncpy(storage_buffer, tmp_buffer, OS_MAXSTR);
            sb_size = OS_MAXSTR - (strlen(storage_buffer) + 1);
            tmp_buffer[0] = '\0';
        } else {
            storage_buffer[0] = '\0';
            sb_size = OS_MAXSTR;
        }
    }
}

/* Handle syslog TCP connections */
void HandleSyslogTCP()
{
    int childcount = 0;
    char srcip[IPSIZE + 1];

    /* Initialize some variables */
    memset(srcip, '\0', IPSIZE + 1);

    /* Connecting to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }

    while (1) {
        /* Wait for the children */
        while (childcount) {
            int wp;
            wp = waitpid((pid_t) - 1, NULL, WNOHANG);
            if (wp < 0) {
                merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
            }

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0) {
                break;
            } else {
                childcount--;
            }
        }

        /* Accept new connections */
        int client_socket = OS_AcceptTCP(logr.sock, srcip, IPSIZE);
        if (client_socket < 0) {
            merror("%s: WARN: Accepting tcp connection from client failed.", ARGV0);
            continue;
        }

        /* Check if IP is allowed here */
        if (OS_IPNotAllowed(srcip)) {
            merror(DENYIP_WARN, ARGV0, srcip);
            close(client_socket);
            continue;
        }

        /* Fork to deal with new client */
        if (fork() == 0) {
            HandleClient(client_socket, srcip);
            exit(0);
        } else {
            childcount++;

            /* Close client socket, since the child is handling it */
            close(client_socket);
            continue;
        }
    }
}

