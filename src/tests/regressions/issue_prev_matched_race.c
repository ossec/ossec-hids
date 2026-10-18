/*
 * Regression: shared if_matched_sid list race across rule-matching threads
 *
 * ANT-2026-M6FZ3J69 / CWE-667
 *
 * sid_prev_matched is owned by the firing rule but searched by watching
 * rules. Appends (and max-size trim frees) used currently_rule->mutex while
 * Search_LastSids used the watcher's mutex — two different locks for one
 * list. With rule_matching_threads > 1, one thread can free an OSListNode
 * in OSList_AddData while another walks lf_node->prev in Search_LastSids.
 *
 * Harness: appender uses the production list lock when linked against a
 * build that exports prev_matched_mutex; otherwise it only takes the firer
 * rule mutex (the buggy pattern). The searcher always calls Search_LastSids
 * (watcher mutex, plus prev_matched_mutex after the fix).
 *
 * Build (from src/):
 *   make TARGET=server
 *   make -f tests/regressions/Makefile issue_prev_matched_race
 *
 * Run:
 *   ./issue_prev_matched_race
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"
#include "analysisd/rules.h"

_Config Config;
__thread time_t c_time;
OSDecoderInfo *NULL_Decoder = NULL;

/* Present after the fix lands in eventinfo.c; NULL when linking unfixed. */
extern pthread_mutex_t prev_matched_mutex __attribute__((weak));

#define MAX_SIZE 8
#define NUM_SEED 16
#define APPEND_ITERS 40000
#define SEARCH_ITERS 40000

static RuleInfo *firer;
static RuleInfo *watcher;
static volatile int stop_workers;

static void Mark_EventNodeDelete(void *data)
{
    Eventinfo *lf = (Eventinfo *)data;
    if (lf) {
        lf->sid_node_to_delete = NULL;
    }
}

static Eventinfo *new_event(RuleInfo *rule, time_t t, const char *srcip)
{
    Eventinfo *lf = calloc(1, sizeof(Eventinfo));
    if (!lf) {
        exit(1);
    }
    lf->fields = calloc(Config.decoder_order_size, sizeof(char *));
    lf->time = t;
    lf->generated_rule = rule;
    lf->srcip = strdup(srcip ? srcip : "198.51.100.1");
    lf->full_log = strdup("regression line");
    return lf;
}

static void lock_list_for_append(void)
{
    if (&prev_matched_mutex) {
        os_mutex_lock(&prev_matched_mutex);
    } else {
        os_mutex_lock(&firer->mutex);
    }
}

static void unlock_list_for_append(void)
{
    if (&prev_matched_mutex) {
        os_mutex_unlock(&prev_matched_mutex);
    } else {
        os_mutex_unlock(&firer->mutex);
    }
}

static void append_event(Eventinfo *lf)
{
    lock_list_for_append();
    if (!OSList_AddData(firer->sid_prev_matched, lf)) {
        fprintf(stderr, "ERROR: OSList_AddData failed\n");
        exit(1);
    }
    lf->sid_node_to_delete = firer->sid_prev_matched->last_node;
    unlock_list_for_append();
}

static void on_fault(int sig)
{
    /* Faults usually land on a worker thread — do not longjmp to main.
     * write/_exit are async-signal-safe. */
    static const char msg[] = "FAIL: fault during concurrent search/append\n";

    (void)sig;
    stop_workers = 1;
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}

static void *appender_thread(void *arg)
{
    int i;
    char ip[32];

    (void)arg;
    for (i = 0; i < APPEND_ITERS && !stop_workers; i++) {
        snprintf(ip, sizeof(ip), "198.51.100.%d", i % 64);
        /* Trimmed Eventinfo pointers are left alive on purpose (Mark_*) so
         * the race is about OSListNode lifetime, not Eventinfo free. */
        append_event(new_event(firer, time(NULL), ip));
        if ((i & 0xff) == 0) {
            sched_yield();
        }
    }
    return NULL;
}

static void *searcher_thread(void *arg)
{
    int i;
    Eventinfo probe;

    (void)arg;
    memset(&probe, 0, sizeof(probe));
    probe.time = time(NULL) + 3600;
    probe.srcip = (char *)"198.51.100.99";
    probe.fields = calloc(Config.decoder_order_size, sizeof(char *));

    for (i = 0; i < SEARCH_ITERS && !stop_workers; i++) {
        (void)Search_LastSids(&probe, watcher);
        if ((i & 0xff) == 0) {
            sched_yield();
        }
    }

    free(probe.fields);
    return NULL;
}

int main(void)
{
    pthread_t ta, ts;
    int i;
    struct sigaction sa;

    printf("=== ANT-2026-M6FZ3J69 prev_matched race regression ===\n");

    /* The bug is that shared sid/group lists have no lock of their own.
     * Fail fast on an unfixed build so CI does not depend on winning a race. */
    if (!&prev_matched_mutex) {
        printf("FAIL: prev_matched_mutex missing — if_matched_sid/group lists "
               "are still locked only by per-rule mutexes\n");
        return 1;
    }
    printf("  ok:   prev_matched_mutex exported\n");

    memset(&Config, 0, sizeof(Config));
    Config.decoder_order_size = 10;
    c_time = time(NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    firer = calloc(1, sizeof(RuleInfo));
    watcher = calloc(1, sizeof(RuleInfo));
    firer->sigid = 31101;
    firer->level = 5;
    watcher->sigid = 31151;
    watcher->level = 10;
    watcher->frequency = 12;
    watcher->timeframe = 120;
    watcher->context_opts = SAME_SRCIP;
    os_mutex_init(&firer->mutex, NULL);
    os_mutex_init(&watcher->mutex, NULL);

    firer->sid_prev_matched = OSList_Create();
    if (!firer->sid_prev_matched ||
            !OSList_SetMaxSize(firer->sid_prev_matched, MAX_SIZE) ||
            !OSList_SetFreeDataPointer(firer->sid_prev_matched, Mark_EventNodeDelete)) {
        fprintf(stderr, "ERROR: list setup failed\n");
        return 1;
    }
    watcher->sid_search = firer->sid_prev_matched;

    for (i = 0; i < NUM_SEED; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "198.51.100.%d", i % 64);
        append_event(new_event(firer, time(NULL), ip));
    }

    stop_workers = 0;
    if (pthread_create(&ta, NULL, appender_thread, NULL) != 0 ||
            pthread_create(&ts, NULL, searcher_thread, NULL) != 0) {
        fprintf(stderr, "ERROR: pthread_create failed\n");
        return 1;
    }
    pthread_join(ta, NULL);
    pthread_join(ts, NULL);

    {
        OSListNode *n;
        int nodes = 0;

        if (&prev_matched_mutex) {
            os_mutex_lock(&prev_matched_mutex);
        }
        n = OSList_GetLastNode(firer->sid_prev_matched);
        while (n) {
            Eventinfo *lf = n->data;
            if (!lf || !lf->srcip) {
                if (&prev_matched_mutex) {
                    os_mutex_unlock(&prev_matched_mutex);
                }
                printf("FAIL: corrupted node during integrity walk\n");
                return 1;
            }
            nodes++;
            n = n->prev;
        }
        if (&prev_matched_mutex) {
            os_mutex_unlock(&prev_matched_mutex);
        }
        if (nodes > MAX_SIZE) {
            printf("FAIL: list grew past max_size (%d > %d)\n", nodes, MAX_SIZE);
            return 1;
        }
        printf("  ok:   list intact after concurrent search/append (%d nodes)\n", nodes);
    }

    printf("PASS: prev_matched race regression\n");
    return 0;
}
