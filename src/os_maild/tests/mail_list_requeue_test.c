/* Standalone test for OS_RequeueMailBatch ordering (no SMTP). */

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

    OS_RequeueMailBatch(batch);

    batch = OS_DrainMailList();
    assert(batch != NULL);
    assert(drain_order_matches(batch, round2, 3));

    while (batch) {
        MailNode *n = batch;

        batch = batch->next;
        FreeMail(n);
    }

    (void)i;
    printf("mail_list_requeue_test: OK\n");
    return (0);
}
