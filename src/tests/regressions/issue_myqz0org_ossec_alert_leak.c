/*
 * ANT-2026-MYQZ0ORG: analysisd_finish_event must free events that were never
 * stored in EventList, even when generated_rule is non-NULL.
 *
 * The ossec-alert plugin decoder sets lf->generated_rule before rule matching.
 * Level-0 and ignore-window exits leave that pointer set without calling
 * OS_AddEvent. Ownership must follow EF_LIST_RETAINED (set only by
 * OS_AddEvent), not generated_rule.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_myqz0org_ossec_alert_leak
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "eventinfo.h"
#include "rules.h"
#include "config.h"

/* Produced by -Wl,--wrap=free */
void *__real_free(void *ptr);

static void *watch_ptr;
static int watch_freed;

void __wrap_free(void *ptr)
{
    if (ptr != NULL && ptr == watch_ptr) {
        watch_freed = 1;
    }
    __real_free(ptr);
}

_Config Config;
OSDecoderInfo *NULL_Decoder = NULL;

static Eventinfo *new_event(RuleInfo *rule)
{
    Eventinfo *lf;

    lf = calloc(1, sizeof(*lf));
    if (!lf) {
        return (NULL);
    }
    lf->generated_rule = rule;
    return (lf);
}

static int expect_freed(const char *label, Eventinfo *lf)
{
    watch_ptr = lf;
    watch_freed = 0;
    analysisd_finish_event(lf);
    if (!watch_freed) {
        printf("  FAIL: %s — Eventinfo not freed\n", label);
        /* Avoid leaking the test allocation if finish_event skipped it. */
        free(lf);
        return (1);
    }
    printf("  ok: %s frees Eventinfo\n", label);
    return (0);
}

static int expect_retained(const char *label, Eventinfo *lf)
{
    watch_ptr = lf;
    watch_freed = 0;
    analysisd_finish_event(lf);
    if (watch_freed) {
        printf("  FAIL: %s — Eventinfo freed despite EF_LIST_RETAINED\n",
               label);
        return (1);
    }
    printf("  ok: %s keeps Eventinfo when retained\n", label);
    free(lf);
    return (0);
}

int main(void)
{
    RuleInfo rule;
    Eventinfo *lf;
    int failed = 0;

    memset(&rule, 0, sizeof(rule));
    rule.level = 0;
    rule.sigid = 5700;
    Config.decoder_order_size = 0;

    printf("=== ANT-2026-MYQZ0ORG: ossec-alert finish_event ownership ===\n");

    /* Decoder-set generated_rule, never added to EventList (level-0 path). */
    lf = new_event(&rule);
    if (!lf) {
        fprintf(stderr, "calloc failed\n");
        return (1);
    }
    failed |= expect_freed("generated_rule set, not retained", lf);

    /* Same shape after OS_AddEvent would mark the event retained. */
    lf = new_event(&rule);
    if (!lf) {
        fprintf(stderr, "calloc failed\n");
        return (1);
    }
    lf->flags |= EF_LIST_RETAINED;
    failed |= expect_retained("generated_rule set, EF_LIST_RETAINED", lf);

    /* Baseline: no rule pointer still frees. */
    lf = new_event(NULL);
    if (!lf) {
        fprintf(stderr, "calloc failed\n");
        return (1);
    }
    failed |= expect_freed("generated_rule NULL, not retained", lf);

    if (failed) {
        printf("\nFAIL: issue_myqz0org_ossec_alert_leak\n");
        return (1);
    }

    printf("\nPASS: issue_myqz0org_ossec_alert_leak\n");
    return (0);
}
