/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Standalone test for OS_RequeueMailBatch ordering and OS_SplitMailBatch (no SMTP). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../headers/pthreads_op.h"
#include "../../headers/debug_op.h"
#include "../maild.h"
#include "../mail_list.h"

#ifndef ARGV0
#define ARGV0 "mail_list_requeue_test"
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

static int drain_order_matches(MailNode *batch, const char **expected, int count)
{
    int i = 0;

    while (batch && i < count) {
        if (!batch->mail || !batch->mail->body) {
            return (0);
        }
        if (strcmp(batch->mail->body, expected[i]) != 0) {
            return (0);
        }
        batch = batch->next;
        i++;
    }

    return (batch == NULL && i == count);
}

static MailMsg *fake_mail(const char *body)
{
    MailMsg *m;

    m = (MailMsg *)calloc(1, sizeof(MailMsg));
    assert(m != NULL);
    m->body = strdup(body);
    assert(m->body != NULL);
    return (m);
}

static MailNode *fake_node(const char *body)
{
    MailNode *n;

    n = (MailNode *)calloc(1, sizeof(MailNode));
    assert(n != NULL);
    n->mail = fake_mail(body);
    return (n);
}

static MailNode *chain_nodes(const char *b1, const char *b2, const char *b3)
{
    MailNode *a = fake_node(b1);
    MailNode *b = fake_node(b2);
    MailNode *c = fake_node(b3);

    a->next = b;
    b->next = c;
    return (a);
}

int main(void)
{
    const char *round1[] = { "oldest", "middle", "newest" };
    const char *round2[] = { "oldest", "middle", "newest" };
    MailNode *batch;
    int i;

    os_mutex_init(&mail_send_mu, NULL);
    OS_CreateMailList(96);

    OS_AddMailtoList(fake_mail("oldest"));
    OS_AddMailtoList(fake_mail("middle"));
    OS_AddMailtoList(fake_mail("newest"));

    batch = OS_DrainMailList();
    assert(batch != NULL);
    assert(drain_order_matches(batch, round1, 3));

    OS_MailListLock();
    OS_RequeueMailBatch(batch);
    OS_MailListUnlock();

    batch = OS_DrainMailList();
    assert(batch != NULL);
    assert(drain_order_matches(batch, round2, 3));

    while (batch) {
        MailNode *n = batch;

        batch = batch->next;
        FreeMail(n);
    }

    /* Requeue overflow: trim must drop multiple tail nodes without UAF. */
    {
        MailNode *cur;
        int nodes = 0;

        OS_CreateMailList(2);
        OS_AddMailtoList(fake_mail("seed"));
        OS_AddMailtoList(fake_mail("live_a"));
        OS_AddMailtoList(fake_mail("live_b"));

        batch = chain_nodes("rq1", "rq2", "rq3");
        batch->next->next->next = fake_node("rq4");
        OS_MailListLock();
        OS_RequeueMailBatch(batch);
        OS_MailListUnlock();

        batch = OS_DrainMailList();
        assert(batch != NULL);
        for (cur = batch; cur; cur = cur->next) {
            nodes++;
        }
        assert(nodes == 2);

        while (batch) {
            MailNode *n = batch;

            batch = batch->next;
            FreeMail(n);
        }
    }

    /* Split: only alerts with the same granular e-mail recipients stay together. */
    {
        char *gran_to[] = { "web1-admin", "pager", NULL };
        const char *no_block[] = { "db1_a", "db1_sms", "db1_b" };
        const char *web1[] = { "web1_a", "web1_b" };
        const int marks[][2] = { { 0, 0 }, { FULL_FORMAT, 0 }, { 0, SMS_FORMAT },
                                 { FULL_FORMAT, 0 }, { 0, 0 } };
        MailNode *group;
        MailNode *cur;

        batch = chain_nodes("db1_a", "web1_a", "db1_sms");
        batch->next->next->next = fake_node("web1_b");
        batch->next->next->next->next = fake_node("db1_b");
        for (cur = batch, i = 0; cur; cur = cur->next, i++) {
            cur->mail->gran_set = (int *)calloc(2, sizeof(int));
            assert(cur->mail->gran_set != NULL);
            memcpy(cur->mail->gran_set, marks[i], sizeof(marks[i]));
        }

        for (i = 0; i < 2; i++) {
            group = OS_SplitMailBatch(&batch, gran_to);
            assert(drain_order_matches(group, i ? web1 : no_block, i ? 2 : 3));
            while (group) {
                MailNode *n = group;

                group = group->next;
                FreeMail(n);
            }
        }
        assert(batch == NULL);
        assert(OS_SplitMailBatch(&batch, gran_to) == NULL);
    }

    printf("mail_list_requeue_test: OK\n");
    return (0);
}
