/*
 * ANT-2026-CZG2BRKO: OS_SplitMailBatch must keep only alerts that share the
 * same FULL_FORMAT granular recipients together. A web1-admin match must
 * not pull db1 alerts into the same SMTP transaction.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_czg2brko_maild_gran_split
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "shared.h"
#include "config/mail-config.h"
#include "os_maild/maild.h"
#include "os_maild/mail_list.h"

const char *__local_name = "issue-czg2brko-maild-gran-split";

pthread_mutex_t mail_send_mu;

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

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

static void free_chain(MailNode *group)
{
    while (group) {
        MailNode *n = group;

        group = group->next;
        FreeMail(n);
    }
}

int main(void)
{
    char *gran_to[] = { "web1-admin", "pager", NULL };
    const char *no_block[] = { "db1_a", "db1_sms", "db1_b" };
    const char *web1[] = { "web1_a", "web1_b" };
    /* FULL_FORMAT=2, SMS_FORMAT=3 — SMS does not join e-mail recipient sets. */
    const int marks[][2] = {
        { 0, 0 },
        { FULL_FORMAT, 0 },
        { 0, SMS_FORMAT },
        { FULL_FORMAT, 0 },
        { 0, 0 }
    };
    MailNode *batch;
    MailNode *group;
    MailNode *cur;
    int i;

    printf("=== ANT-2026-CZG2BRKO: OS_SplitMailBatch by FULL_FORMAT set ===\n");

    os_mutex_init(&mail_send_mu, NULL);

    batch = fake_node("db1_a");
    batch->next = fake_node("web1_a");
    batch->next->next = fake_node("db1_sms");
    batch->next->next->next = fake_node("web1_b");
    batch->next->next->next->next = fake_node("db1_b");

    for (cur = batch, i = 0; cur; cur = cur->next, i++) {
        cur->mail->gran_set = (int *)calloc(2, sizeof(int));
        assert(cur->mail->gran_set != NULL);
        memcpy(cur->mail->gran_set, marks[i], sizeof(marks[i]));
    }

    group = OS_SplitMailBatch(&batch, gran_to);
    CHECK(drain_order_matches(group, no_block, 3),
          "first group is db1 alerts (no FULL_FORMAT web1-admin)");
    free_chain(group);

    group = OS_SplitMailBatch(&batch, gran_to);
    CHECK(drain_order_matches(group, web1, 2),
          "second group is web1 alerts only");
    free_chain(group);

    CHECK(batch == NULL, "batch fully consumed");
    CHECK(OS_SplitMailBatch(&batch, gran_to) == NULL, "empty batch returns NULL");

    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
