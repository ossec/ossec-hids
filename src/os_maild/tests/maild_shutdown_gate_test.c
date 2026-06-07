/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * Standalone test for maild shutdown exit gating with SMS backlog.
 */

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
#define ARGV0 "maild_shutdown_gate_test"
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

/* Same condition as maild.c shutdown loop after maild_shutdown_drain(). */
static int maild_shutdown_complete(int active, int sms_pending, int mail_pending)
{
    return active == 0 && !sms_pending && !mail_pending;
}

int main(void)
{
    MailMsg *msg;
    int active = 0;
    int iterations = 0;

    os_mutex_init(&mail_send_mu, NULL);
    OS_SmsQueueInit();

    OS_SmsEnqueue(fake_sms("one"));
    OS_SmsEnqueue(fake_sms("two"));
    OS_SmsEnqueue(fake_sms("three"));

    assert(!maild_shutdown_complete(0, 1, 0));

    while (!maild_shutdown_complete(active, OS_SmsQueuePending(), 0)) {
        if (active == 0 && OS_SmsQueuePending()) {
            msg = OS_SmsDequeue();
            assert(msg != NULL);
            FreeMailMsg(msg);
        }
        iterations++;
        assert(iterations < 16);
    }

    assert(OS_SmsDequeue() == NULL);
    printf("maild_shutdown_gate_test: OK\n");
    return 0;
}
