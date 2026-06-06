/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sms_queue.h"
#include "mail_list.h"

typedef struct sms_queue_node {
    MailMsg *msg;
    struct sms_queue_node *next;
} sms_queue_node;

static sms_queue_node *sms_head = NULL;
static sms_queue_node *sms_tail = NULL;
static pthread_mutex_t sms_queue_mu;
static int sms_queue_ready = 0;

void OS_SmsQueueInit(void)
{
    if (!sms_queue_ready) {
        os_mutex_init(&sms_queue_mu, NULL);
        sms_queue_ready = 1;
    }

    OS_SmsQueueClear();
}

void OS_SmsEnqueue(MailMsg *msg)
{
    sms_queue_node *node;

    if (!msg) {
        return;
    }

    if (!sms_queue_ready) {
        OS_SmsQueueInit();
    }

    os_calloc(1, sizeof(sms_queue_node), node);
    node->msg = msg;

    os_mutex_lock(&sms_queue_mu);
    if (sms_tail) {
        sms_tail->next = node;
        sms_tail = node;
    } else {
        sms_head = sms_tail = node;
    }
    os_mutex_unlock(&sms_queue_mu);
}

MailMsg *OS_SmsDequeue(void)
{
    sms_queue_node *node;
    MailMsg *msg = NULL;

    if (!sms_queue_ready) {
        return NULL;
    }

    os_mutex_lock(&sms_queue_mu);
    node = sms_head;
    if (node) {
        sms_head = node->next;
        if (!sms_head) {
            sms_tail = NULL;
        }
        msg = node->msg;
        free(node);
    }
    os_mutex_unlock(&sms_queue_mu);

    return msg;
}

void OS_SmsRequeueFront(MailMsg *msg)
{
    sms_queue_node *node;

    if (!msg) {
        return;
    }

    if (!sms_queue_ready) {
        OS_SmsQueueInit();
    }

    os_calloc(1, sizeof(sms_queue_node), node);
    node->msg = msg;

    os_mutex_lock(&sms_queue_mu);
    node->next = sms_head;
    sms_head = node;
    if (!sms_tail) {
        sms_tail = node;
    }
    os_mutex_unlock(&sms_queue_mu);
}

int OS_SmsQueuePending(void)
{
    int pending = 0;

    if (!sms_queue_ready) {
        return 0;
    }

    os_mutex_lock(&sms_queue_mu);
    pending = (sms_head != NULL);
    os_mutex_unlock(&sms_queue_mu);

    return pending;
}

void OS_SmsQueueClear(void)
{
    MailMsg *msg;

    if (!sms_queue_ready) {
        sms_head = NULL;
        sms_tail = NULL;
        return;
    }

    while ((msg = OS_SmsDequeue()) != NULL) {
        FreeMailMsg(msg);
    }
}
