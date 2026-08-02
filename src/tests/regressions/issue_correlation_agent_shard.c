/*
 * Regression: location-hashed EventList shards isolate Search_LastEvents;
 * if_matched_sid (global sid_search list) still correlates across locations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"
#include "analysisd/rules.h"
#include "analysisd/correlation_shard.h"

_Config Config;
__thread time_t c_time;
OSDecoderInfo null_decoder_storage;
OSDecoderInfo *NULL_Decoder = &null_decoder_storage;
const char *__local_name = "issue_correlation_agent_shard";

int getDefine_Int(const char *section, const char *key, int min, int max)
{
    (void)section;
    (void)key;
    (void)max;
    return min;
}

static Eventinfo *make_event(const char *location, const char *log, time_t when)
{
    Eventinfo *lf = (Eventinfo *)calloc(1, sizeof(Eventinfo));

    if (!lf) {
        return NULL;
    }

    lf->location = strdup(location);
    lf->hostname = lf->location;
    lf->full_log = strdup(log);
    lf->log = lf->full_log;
    lf->time = when;
    lf->decoder_info = NULL_Decoder;
    lf->matched = 0;
    lf->srcip = strdup("10.0.0.1");

    return lf;
}

static void free_event_shallow(Eventinfo *lf)
{
    if (!lf) {
        return;
    }
    free(lf->location);
    free(lf->full_log);
    free(lf->srcip);
    free(lf);
}

static int test_eventlist_shard_isolation(void)
{
    EventList *shard0;
    EventList *shard1;
    RuleInfo freq_rule;
    Eventinfo *probe;
    Eventinfo *matched;
    Eventinfo *a;
    Eventinfo *b;
    time_t now = time(NULL);
    unsigned int id_a;
    unsigned int id_b;
    int i;

    c_time = now;
    memset(&freq_rule, 0, sizeof(freq_rule));

    shard0 = OS_EventList_Create(Config.memorysize);
    shard1 = OS_EventList_Create(Config.memorysize);
    if (!shard0 || !shard1) {
        fprintf(stderr, "ERROR: OS_EventList_Create failed\n");
        return 1;
    }

    a = make_event("(001)->10.0.0.1", "agent A", now);
    b = make_event("(002)->10.0.0.2", "agent B", now);
    if (!a || !b) {
        fprintf(stderr, "ERROR: make_event failed\n");
        return 1;
    }

    id_a = analysisd_shard_id(a, 2);
    id_b = analysisd_shard_id(b, 2);
    if (analysisd_shard_id(a, 8) != analysisd_shard_id(a, 8)) {
        fprintf(stderr, "ERROR: analysisd_shard_id unstable\n");
        return 1;
    }
    printf("PASS: analysisd_shard_id stable (a=%u b=%u under 2 shards)\n", id_a, id_b);

    os_mutex_init(&freq_rule.mutex, NULL);
    freq_rule.sigid = 100;
    freq_rule.level = 5;
    freq_rule.timeframe = 300;
    freq_rule.frequency = 0;
    freq_rule.context = 1;
    freq_rule.context_opts = SAME_SRCIP;
    os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), freq_rule.last_events);

    analysisd_set_event_list(id_a == 0 ? shard1 : shard0);
    for (i = 0; i < 50; i++) {
        Eventinfo *noise = make_event("(002)->10.0.0.2", "noise", now + i);

        if (!noise) {
            fprintf(stderr, "ERROR: noise alloc failed\n");
            return 1;
        }
        noise->generated_rule = &freq_rule;
        OS_AddEvent(noise);
    }

    analysisd_set_event_list(id_a == 0 ? shard0 : shard1);
    probe = make_event("(001)->10.0.0.1", "probe", now + 100);
    if (!probe) {
        fprintf(stderr, "ERROR: probe alloc failed\n");
        return 1;
    }

    matched = Search_LastEvents(probe, &freq_rule);
    if (matched) {
        fprintf(stderr, "ERROR: Search_LastEvents saw other shard's noise\n");
        return 1;
    }

    {
        Eventinfo *hist = make_event("(001)->10.0.0.1", "history", now + 50);

        if (!hist) {
            fprintf(stderr, "ERROR: history alloc failed\n");
            return 1;
        }
        hist->generated_rule = &freq_rule;
        OS_AddEvent(hist);
    }

    matched = Search_LastEvents(probe, &freq_rule);
    if (!matched) {
        fprintf(stderr, "ERROR: Search_LastEvents missed same-shard history\n");
        return 1;
    }

    printf("PASS: location-hashed EventList shard isolation\n");

    free_event_shallow(a);
    free_event_shallow(b);
    free_event_shallow(probe);
    OS_EventList_Destroy(shard0);
    OS_EventList_Destroy(shard1);
    return 0;
}

/* if_matched_sid uses a shared OSList; history from agent A/B both count. */
static int test_if_matched_sid_cross_location(void)
{
    RuleInfo parent_rule;
    RuleInfo child_rule;
    OSList *sid_list;
    Eventinfo *from_a;
    Eventinfo *from_b;
    Eventinfo *probe;
    Eventinfo *matched;
    time_t now = time(NULL);

    c_time = now;
    memset(&parent_rule, 0, sizeof(parent_rule));
    memset(&child_rule, 0, sizeof(child_rule));

    sid_list = OSList_Create();
    if (!sid_list || !OSList_SetMaxSize(sid_list, 128)) {
        fprintf(stderr, "ERROR: OSList_Create/SetMaxSize failed\n");
        return 1;
    }

    os_mutex_init(&parent_rule.mutex, NULL);
    parent_rule.sigid = 5701;
    parent_rule.level = 3;
    parent_rule.sid_prev_matched = sid_list;

    os_mutex_init(&child_rule.mutex, NULL);
    child_rule.sigid = 5710;
    child_rule.level = 10;
    child_rule.timeframe = 300;
    child_rule.frequency = 1; /* need 2 prior fires */
    child_rule.if_matched_sid = 5701;
    child_rule.sid_search = sid_list;
    child_rule.context = 1;
    os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), child_rule.last_events);

    from_a = make_event("(001)->10.0.0.1", "fail A", now);
    from_b = make_event("(002)->10.0.0.2", "fail B", now + 1);
    probe = make_event("(003)->10.0.0.3", "fail C", now + 2);
    if (!from_a || !from_b || !probe) {
        fprintf(stderr, "ERROR: make_event failed for sid test\n");
        return 1;
    }

    from_a->generated_rule = &parent_rule;
    from_b->generated_rule = &parent_rule;
    if (!OSList_AddData(sid_list, from_a) || !OSList_AddData(sid_list, from_b)) {
        fprintf(stderr, "ERROR: OSList_AddData failed\n");
        return 1;
    }

    /* Pure EventList path cannot see cross-agent history (different shard keys). */
    {
        EventList *empty = OS_EventList_Create(Config.memorysize);
        RuleInfo local_only;

        if (!empty) {
            fprintf(stderr, "ERROR: empty EventList create failed\n");
            return 1;
        }
        memset(&local_only, 0, sizeof(local_only));
        os_mutex_init(&local_only.mutex, NULL);
        local_only.sigid = 99;
        local_only.level = 5;
        local_only.timeframe = 300;
        local_only.frequency = 1;
        local_only.context = 1;
        os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), local_only.last_events);
        analysisd_set_event_list(empty);
        matched = Search_LastEvents(probe, &local_only);
        if (matched) {
            fprintf(stderr, "ERROR: empty EventList unexpectedly matched\n");
            return 1;
        }
        OS_EventList_Destroy(empty);
    }

    matched = Search_LastSids(probe, &child_rule);
    if (!matched) {
        fprintf(stderr, "ERROR: Search_LastSids missed cross-location parent fires\n");
        return 1;
    }

    printf("PASS: if_matched_sid Search_LastSids correlates across locations\n");
    return 0;
}

int main(void)
{
    memset(&Config, 0, sizeof(Config));
    memset(&null_decoder_storage, 0, sizeof(null_decoder_storage));
    null_decoder_storage.type = SYSLOG;
    Config.decoder_order_size = 8;
    Config.memorysize = 8192;

    if (test_eventlist_shard_isolation() != 0) {
        return 1;
    }
    if (test_if_matched_sid_cross_location() != 0) {
        return 1;
    }

    return 0;
}
