/*
 * Regression test for Issue 1079: frequency alert context shows wrong logs.
 *
 * Search_LastSids copies full_log strings, then OS_MoveRuleLastEvents transfers
 * them onto the firing Eventinfo (alert_last_events). Raw pointers to
 * Eventinfo->full_log must not be used — they become stale when those events
 * leave the sid list / ring.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile.1079
 *
 * Run:
 *   ./issue_1079_last_events_uaf
 *
 * With valgrind:
 *   valgrind --error-exitcode=42 --leak-check=no -q ./issue_1079_last_events_uaf
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"
#include "analysisd/rules.h"

/* Globals required by analysisd code */
_Config Config;
__thread time_t c_time;
OSDecoderInfo *NULL_Decoder = NULL;

static Eventinfo *make_event(const char *full_log, const char *srcip, time_t when)
{
    Eventinfo *lf;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_strdup(full_log, lf->full_log);
    lf->log = lf->full_log;
    os_strdup(srcip, lf->srcip);
    lf->time = when;
    lf->size = strlen(lf->log);

    return lf;
}

static void setup_freq_rule(RuleInfo *rule5710, RuleInfo *rule5712)
{
    int ii;

    memset(rule5710, 0, sizeof(RuleInfo));
    rule5710->sigid = 5710;
    rule5710->level = 5;
#ifndef WIN32
    os_mutex_init(&rule5710->mutex, NULL);
#endif

    rule5710->sid_prev_matched = OSList_Create();
    if (!rule5710->sid_prev_matched) {
        ErrorExit(MEM_ERROR, "issue_1079", errno, strerror(errno));
    }

    memset(rule5712, 0, sizeof(RuleInfo));
    rule5712->sigid = 5712;
    rule5712->level = 10;
    rule5712->frequency = 2;
    rule5712->timeframe = 120;
    rule5712->context = 1;
    rule5712->context_opts = SAME_SRCIP;
    rule5712->sid_search = rule5710->sid_prev_matched;
    rule5712->last_events_copied = 0;
#ifndef WIN32
    os_mutex_init(&rule5712->mutex, NULL);
#endif

    os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), rule5712->last_events);
    for (ii = 0; ii <= MAX_LAST_EVENTS; ii++) {
        rule5712->last_events[ii] = NULL;
    }
}

static int add_to_sid_list(RuleInfo *rule5710, Eventinfo *lf)
{
    if (!OSList_AddData(rule5710->sid_prev_matched, lf)) {
        return (0);
    }

    lf->generated_rule = rule5710;
    lf->sid_node_to_delete = rule5710->sid_prev_matched->last_node;
    return (1);
}

int main(void)
{
    RuleInfo rule5710;
    RuleInfo rule5712;
    Eventinfo *failures[3];
    Eventinfo *trigger;
    Eventinfo *matched;
    const char *srcip = "192.168.20.26";
    const char *accepted =
        "Mar  1 13:06:53 BOX_B sshd[28131]: Accepted publickey for oracle from 192.168.20.26 port 38562 ssh2";
    int ii;

    memset(&Config, 0, sizeof(_Config));
    Config.decoder_order_size = 10;
    c_time = time(NULL);

    setup_freq_rule(&rule5710, &rule5712);

    failures[0] = make_event(
        "Mar  1 13:06:40 BOX_A sshd[23510]: Invalid user bad1 from 192.168.20.26",
        srcip, c_time - 30);
    failures[1] = make_event(
        "Mar  1 13:06:45 BOX_A sshd[23512]: Invalid user bad2 from 192.168.20.26",
        srcip, c_time - 25);
    failures[2] = make_event(
        "Mar  1 13:06:50 BOX_A sshd[23514]: Invalid user bad3 from 192.168.20.26",
        srcip, c_time - 20);

    for (ii = 0; ii < 3; ii++) {
        if (!add_to_sid_list(&rule5710, failures[ii])) {
            fprintf(stderr, "ERROR: unable to add failure event %d to sid list\n", ii);
            return (1);
        }
    }

    trigger = make_event(
        "Mar  1 13:07:04 BOX_A sshd[23518]: Invalid user  from 192.168.20.26",
        srcip, c_time);

    matched = Search_LastSids(trigger, &rule5712);
    if (!matched) {
        fprintf(stderr, "ERROR: Search_LastSids did not match (expected rule 5712)\n");
        return (1);
    }

    /* Ownership moved onto the firing event under rule->mutex. */
    if (!trigger->alert_last_events || !trigger->alert_last_events[0] ||
        !strstr(trigger->alert_last_events[0], "Invalid user")) {
        fprintf(stderr, "ERROR: expected Invalid user in trigger->alert_last_events[0]\n");
        return (1);
    }

    if (rule5712.last_events_copied) {
        fprintf(stderr, "ERROR: rule last_events should be cleared after Move\n");
        return (1);
    }

    /* Free the event that originally backed the sampled log. */
    Free_Eventinfo(failures[2]);

    if (!trigger->alert_last_events[0] ||
        !strstr(trigger->alert_last_events[0], "Invalid user")) {
        fprintf(stderr, "ERROR: alert_last_events[0] corrupted after source event was freed\n");
        return (1);
    }

    if (strstr(trigger->alert_last_events[0], "Accepted publickey") != NULL) {
        fprintf(stderr, "ERROR: alert_last_events[0] shows unrelated success log after free\n");
        return (1);
    }

    /* Deliberately reuse freed memory; copies must remain stable. */
    for (ii = 0; ii < 4096; ii++) {
        char *block = (char *)malloc(strlen(accepted) + 64);

        if (!block) {
            break;
        }

        snprintf(block, strlen(accepted) + 64, "%s", accepted);
        free(block);
    }

    if (strstr(trigger->alert_last_events[0], "Accepted publickey") != NULL) {
        fprintf(stderr, "ERROR: alert_last_events[0] overwritten by unrelated allocator traffic\n");
        return (1);
    }

    printf("PASS: last_events retains correct log text after source Eventinfo is freed\n");
    printf("  last_events[0]: %s\n", trigger->alert_last_events[0]);

    Free_Eventinfo(failures[0]);
    Free_Eventinfo(failures[1]);
    Free_Eventinfo(trigger);

    while (rule5710.sid_prev_matched->currently_size > 0) {
        OSList_DeleteOldestNode(rule5710.sid_prev_matched);
    }

    free(rule5712.last_events);
    free(rule5710.sid_prev_matched);

    return (0);
}
