/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>

#include "shared.h"
#include "remoted.h"
#include "os_net/os_net.h"

/* pthread send_msg mutex */
static pthread_mutex_t sendmsg_mutex;

/* pthread key update mutex */
static pthread_mutex_t keyupdate_mutex;


/* Initializes mutex */
void keyupdate_init()
{
    /* Initialize mutex */
    pthread_mutex_init(&keyupdate_mutex, NULL);
}

void key_lock()
{
    if (pthread_mutex_lock(&keyupdate_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
    }
}

void key_unlock()
{
    if (pthread_mutex_unlock(&keyupdate_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
    }
}

/* Check for key updates */
int check_keyupdate()
{
    /* Check key for updates */
    if (!OS_CheckUpdateKeys(&keys)) {
        return (0);
    }

    key_lock();

    /* Lock before using */
    if (pthread_mutex_lock(&sendmsg_mutex) != 0) {
        key_unlock();
        merror(MUTEX_ERROR, ARGV0);
        return (0);
    }

    if (OS_UpdateKeys(&keys)) {
        if (pthread_mutex_unlock(&sendmsg_mutex) != 0) {
            merror(MUTEX_ERROR, ARGV0);
        }
        key_unlock();
        return (1);
    }

    if (pthread_mutex_unlock(&sendmsg_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
    }
    key_unlock();

    return (0);
}

/* Initialize send_msg */
void send_msg_init()
{
    /* Initialize mutex */
    pthread_mutex_init(&sendmsg_mutex, NULL);
}


/*
 * Send message to an agent
 * Returns -1 on error
 */

int send_msg(unsigned int agentid, const char *msg)
{
    size_t msg_size, sa_size;
    char crypt_msg[OS_MAXSTR + 1];
    struct sockaddr * dest_sa;

    /* If we don't have the agent id, ignore it */
    if (keys.keyentries[agentid]->rcvd < (time(0) - (2 * NOTIFY_TIME))) {
        return (-1);
    }

    msg_size = CreateSecMSG(&keys, msg, crypt_msg, agentid);
    if (msg_size == 0) {
        merror(SEC_ERROR, ARGV0);
        return (-1);
    }

    /* Lock before using */
    if (pthread_mutex_lock(&sendmsg_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
        return (-1);
    }

    /* Send initial message */
    dest_sa = (struct sockaddr *)&keys.keyentries[agentid]->peer_info;
    sa_size = (dest_sa->sa_family == AF_INET) ?
              sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

   /*
    * Because we handle multiple IP addresses, we won't know what interfaces
    * are active for network communication until we receive something on one
    * of them.  This is a work around in the event we need to send before
    * we have identified the working interface in secure.c. (dgs - 2/26/18)
    */

    if (logr.sock == 0) {
        int i, ok = 0;

        /* socket not established - try current sockets */
        for (i = 0; i < logr.netinfo->fdcnt; i++) {
            if (sendto(logr.netinfo->fds[i], crypt_msg, msg_size, 0,
                       dest_sa, sa_size) < 0) {
                continue;
            }

            ok = 1;
            break;
        }

        /* if we tried all the sockets and noe of them worked, send an error */
        if (ok == 0) {       
            merror(SEND_ERROR, ARGV0, keys.keyentries[agentid]->id);
        }
    } else {
        /* working socket identified in secure.c */
        if (sendto(logr.sock, crypt_msg, msg_size, 0, dest_sa, sa_size) < 0) {
            merror(SEND_ERROR, ARGV0, keys.keyentries[agentid]->id);
        }
    }

    /* Unlock mutex */
    if (pthread_mutex_unlock(&sendmsg_mutex) != 0) {
        merror(MUTEX_ERROR, ARGV0);
        return (-1);
    }

    return (0);
}

