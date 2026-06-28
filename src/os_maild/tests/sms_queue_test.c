/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Standalone test for SMS pending queue ordering. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../headers/pthreads_op.h"
#include "../../headers/debug_op.h"
#include "../maild.h"
#include "../mail_list.h"
#include "../sms_queue.h"

#ifndef ARGV0
#define ARGV0 "sms_queue_test"
#endif

pthread_mutex_t mail_send_mu;

int getDefine_Int(const char *section, const char *key, int min, int max)
{
    (void)section;
    (void)key;
    (void)min;
    (void)max;
    return (1);
}

static MailMsg *fake_sms(const char *body)
{
    MailMsg *m;

    m = (MailMsg *)calloc(1, sizeof(MailMsg));
    assert(m != NULL);
    m->body = strdup(body);
    assert(m->body != NULL);
    return (m);
}

int main(void)
{
    MailMsg *a;
    MailMsg *b;
    MailMsg *c;

    os_mutex_init(&mail_send_mu, NULL);
    OS_SmsQueueInit();

    OS_SmsEnqueue(fake_sms("first"));
    OS_SmsEnqueue(fake_sms("second"));
    OS_SmsEnqueue(fake_sms("third"));

    assert(OS_SmsQueuePending() == 1);

    a = OS_SmsDequeue();
    b = OS_SmsDequeue();
    c = OS_SmsDequeue();

    assert(a && b && c);
    assert(strcmp(a->body, "first") == 0);
    assert(strcmp(b->body, "second") == 0);
    assert(strcmp(c->body, "third") == 0);
    assert(OS_SmsDequeue() == NULL);

    OS_SmsRequeueFront(c);
    assert(strcmp(OS_SmsDequeue()->body, "third") == 0);

    FreeMailMsg(a);
    FreeMailMsg(b);
    FreeMailMsg(c);

    printf("sms_queue_test: OK\n");
    return (0);
}
