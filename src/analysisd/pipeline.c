/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Parity board (nested Wazuh analysisd vs Atomicorp):
 * - Always-on multi-threaded pipeline on Linux (no pipeline_enabled gate).
 * - TLS regex_matching + match_data per decode/process worker
 *   (os_regex_set_thread_match), not process-global regex state.
 * - Staged drain shutdown (input → decode → shard output → writers) with
 *   timed joins and fail-closed _exit(1); nested historically exit(1) early.
 * - No SCA / syscollector / w_* helpers from nested.
 * - Sharded EventList (one list + one decode-output queue per rule-matching
 *   thread) exceeds nested's single contended global EventList + mutex model.
 * - Ticket alert IDs via analysisd_claim_alert_id() for async alert writers.
 * - Async FTS writer (writer_queue_fts): match path updates memory under
 *   fts_mutex, enqueues a strdup'd line; FTS_Fprintf/Flush under fts_write_lock.
 * - Dual input demux (1 recv + N route workers) exceeds nested's single demux.
 * - Per-agent rootcheck FILE locks; hostinfo under process-wide mutex.
 */

#ifndef WIN32

/* For pthread_timedjoin_np (Linux). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "shared.h"
#include "os_net/os_net.h"
#include "pipeline.h"
#include "state.h"
#include "analysisd.h"
#include "queue_op.h"
#include "correlation_shard.h"
#include "accumulator.h"
#include "decoders/decoder.h"
#include "cleanevent.h"
#include "config.h"
#include "output/jsonout.h"
#include "alerts/log.h"
#include "alerts/getloglocation.h"
#include "fts.h"

extern int hourly_events;
extern FILE *_aflog;

os_queue *decode_queue_event_input = NULL;
os_queue *decode_queue_syscheck_input = NULL;
os_queue *decode_queue_rootcheck_input = NULL;
os_queue *decode_queue_hostinfo_input = NULL;
os_queue **decode_queue_event_output = NULL;
int decode_queue_event_output_count = 0;
os_queue *writer_queue_log = NULL;
os_queue *writer_queue_statistical = NULL;
os_queue *writer_queue_archive = NULL;
os_queue *writer_queue_firewall = NULL;
os_queue *writer_queue_fts = NULL;
os_queue *raw_input_queue = NULL;

static volatile sig_atomic_t analysisd_shutting_down = 0;
static volatile sig_atomic_t pipeline_m_queue = -1;
static volatile long alert_ticket = 0;

static int cfg_event_threads = 1;
static int cfg_rule_matching_threads = 1;
static int cfg_syscheck_threads = 1;
static int cfg_rootcheck_threads = 1;
static int cfg_hostinfo_threads = 1;
static int cfg_input_demux_threads = 2;
static int cfg_decode_event_queue_size = 16384;
static int cfg_raw_input_queue_size = 16384;
static int cfg_decode_syscheck_queue_size = 16384;
static int cfg_decode_rootcheck_queue_size = 16384;
static int cfg_decode_hostinfo_queue_size = 16384;
static int cfg_decode_output_queue_size = 16384;
static int cfg_alerts_queue_size = 16384;
static int cfg_statistical_queue_size = 16384;
static int cfg_archives_queue_size = 16384;
static int cfg_firewall_queue_size = 16384;
static int cfg_fts_queue_size = 16384;

/* Mid-pipe push waits (ms); resolved once in analysisd_pipeline_run. */
static int cfg_raw_input_push_wait_ms = 25;
static int cfg_demux_push_wait_ms = 50;
static int cfg_shard_push_wait_ms = 75;
static int cfg_alerts_push_wait_ms = 100;

#define ANALYSISD_INPUT_DEMUX_THREADS_MAX 8
#define ANALYSISD_PUSH_WAIT_MS_MAX 5000

static pthread_t input_recv_thread_id;
static pthread_t *input_demux_threads = NULL;
static int input_demux_thread_count = 0;
static pthread_t *decode_event_threads = NULL;
static pthread_t *decode_syscheck_threads = NULL;
static pthread_t *decode_rootcheck_threads = NULL;
static pthread_t *decode_hostinfo_threads = NULL;
static pthread_t *process_event_threads = NULL;
static pthread_t writer_log_thread_id;
static pthread_t writer_statistical_thread_id;
static pthread_t writer_archive_thread_id;
static pthread_t writer_firewall_thread_id;
static pthread_t writer_fts_thread_id;
static pthread_t state_thread_id;
static pthread_mutex_t writer_threads_mutex = PTHREAD_MUTEX_INITIALIZER;

static int decode_event_thread_count = 0;
static int decode_syscheck_thread_count = 0;
static int decode_rootcheck_thread_count = 0;
static int decode_hostinfo_thread_count = 0;
static int process_event_thread_count = 0;

static EventList **shard_lists = NULL;
static OSHash **shard_acm_stores = NULL;

/* Rate-limit drop warnings to once per this many seconds. */
#define ANALYSISD_DROP_WARN_INTERVAL_SEC 30

static time_t analysisd_last_drop_warn = 0;

static void analysisd_warn_dropped(const char *where)
{
    time_t now = time(NULL);
    unsigned int dropped;
    unsigned int shard_drop;
    unsigned int arch_drop;

    if (analysisd_shutting_down) {
        return;
    }

    if (analysisd_last_drop_warn != 0 &&
        (now - analysisd_last_drop_warn) < ANALYSISD_DROP_WARN_INTERVAL_SEC) {
        return;
    }
    analysisd_last_drop_warn = now;

    dropped = analysisd_get_dropped_events();
    shard_drop = analysisd_get_shard_dropped();
    arch_drop = analysisd_get_archives_dropped();
    merror("%s: WARN: pipeline queue pressure (%s): events_dropped=%u "
           "shard_dropped=%u archives_dropped=%u. Check .state and raise "
           "queue sizes or reduce EPS; events may be lost before rule match.",
           ARGV0, where ? where : "unknown", dropped, shard_drop, arch_drop);
}

static void analysisd_abs_timeout_ms(struct timespec *ts, int ms)
{
    if (clock_gettime(CLOCK_REALTIME, ts) != 0) {
        ts->tv_sec = time(NULL) + (ms / 1000);
        ts->tv_nsec = (long)(ms % 1000) * 1000000L;
        return;
    }
    ts->tv_nsec += (long)ms * 1000000L;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

/* Resolve thread count: 0 means auto = min(online CPUs, 32). */
static int analysisd_resolve_threads(const char *opt_name)
{
    int n;
    long cpus;

    n = getDefine_Int("analysisd", opt_name, 0, 32);
    if (n > 0) {
        return n;
    }

    cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus < 1) {
        cpus = 1;
    }
    if (cpus > 32) {
        cpus = 32;
    }

    verbose("%s: INFO: analysisd.%s=0; using %ld threads (CPU count).",
            ARGV0, opt_name, cpus);
    return (int)cpus;
}

static int analysisd_resolve_queue_size(const char *opt_name)
{
    return getDefine_Int("analysisd", opt_name, 128, 2000000);
}

/* Push wait before drop: 0 = immediate (Nested-like non-wait where applicable). */
static int analysisd_resolve_push_wait_ms(const char *opt_name, int default_ms)
{
    (void)default_ms; /* Documented fallback; value comes from internal_options.conf. */
    return getDefine_Int("analysisd", opt_name, 0, ANALYSISD_PUSH_WAIT_MS_MAX);
}

static int analysisd_queue_push_wait(os_queue *queue, void *data, int wait_ms)
{
    struct timespec ts;

    if (!queue) {
        return -1;
    }
    if (wait_ms <= 0) {
        return os_queue_push_ex(queue, data);
    }
    analysisd_abs_timeout_ms(&ts, wait_ms);
    return os_queue_push_ex_timedwait(queue, data, &ts);
}

static void analysisd_writer_sync_alert(Eventinfo *lf)
{
    /* Prefer ticketed IDs; never ftell(_aflog) here — that races log rollover. */
    if (lf && lf->alert_id) {
        __crt_ftell = lf->alert_id;
    } else {
        __crt_ftell = 0;
    }
    if (Config.custom_alert_output) {
        OS_CustomLog(lf, Config.custom_alert_output_format);
    } else {
        OS_Log(lf);
    }
    if (Config.jsonout_output) {
        jsonout_output_event(lf);
    }
}

long analysisd_claim_alert_id(void)
{
    return __sync_add_and_fetch(&alert_ticket, 1);
}

void analysisd_init_queues(void)
{
    int i;

    /* Parallel demux after single Unix recv. */
    raw_input_queue = os_queue_init((size_t)cfg_raw_input_queue_size);

    decode_queue_event_input = os_queue_init((size_t)cfg_decode_event_queue_size);
    decode_queue_syscheck_input = os_queue_init((size_t)cfg_decode_syscheck_queue_size);
    decode_queue_rootcheck_input = os_queue_init((size_t)cfg_decode_rootcheck_queue_size);
    decode_queue_hostinfo_input = os_queue_init((size_t)cfg_decode_hostinfo_queue_size);

    decode_queue_event_output_count = process_event_thread_count;
    os_calloc((size_t)decode_queue_event_output_count, sizeof(os_queue *),
              decode_queue_event_output);
    for (i = 0; i < decode_queue_event_output_count; i++) {
        decode_queue_event_output[i] = os_queue_init((size_t)cfg_decode_output_queue_size);
    }

    writer_queue_log = os_queue_init((size_t)cfg_alerts_queue_size);
    writer_queue_statistical = os_queue_init((size_t)cfg_statistical_queue_size);
    writer_queue_archive = os_queue_init((size_t)cfg_archives_queue_size);
    writer_queue_firewall = os_queue_init((size_t)cfg_firewall_queue_size);
    writer_queue_fts = os_queue_init((size_t)cfg_fts_queue_size);
}

void analysisd_destroy_queues(void)
{
    int i;

    os_queue_destroy(raw_input_queue);
    os_queue_destroy(decode_queue_event_input);
    os_queue_destroy(decode_queue_syscheck_input);
    os_queue_destroy(decode_queue_rootcheck_input);
    os_queue_destroy(decode_queue_hostinfo_input);

    if (decode_queue_event_output) {
        for (i = 0; i < decode_queue_event_output_count; i++) {
            os_queue_destroy(decode_queue_event_output[i]);
            decode_queue_event_output[i] = NULL;
        }
        free(decode_queue_event_output);
        decode_queue_event_output = NULL;
    }
    decode_queue_event_output_count = 0;

    os_queue_destroy(writer_queue_log);
    os_queue_destroy(writer_queue_statistical);
    os_queue_destroy(writer_queue_archive);
    os_queue_destroy(writer_queue_firewall);
    os_queue_destroy(writer_queue_fts);

    raw_input_queue = NULL;
    decode_queue_event_input = NULL;
    decode_queue_syscheck_input = NULL;
    decode_queue_rootcheck_input = NULL;
    decode_queue_hostinfo_input = NULL;
    writer_queue_log = NULL;
    writer_queue_statistical = NULL;
    writer_queue_archive = NULL;
    writer_queue_firewall = NULL;
    writer_queue_fts = NULL;
}

static os_queue *analysisd_route_queue(char mq_prefix)
{
    switch (mq_prefix) {
        case SYSCHECK_MQ:
            return decode_queue_syscheck_input;
        case ROOTCHECK_MQ:
            return decode_queue_rootcheck_input;
        case HOSTINFO_MQ:
            return decode_queue_hostinfo_input;
        default:
            return decode_queue_event_input;
    }
}

static int analysisd_push_decoded(Eventinfo *lf)
{
    unsigned int shard;

    if (!lf || !decode_queue_event_output || process_event_thread_count <= 0) {
        Free_Eventinfo(lf);
        return -1;
    }

    shard = analysisd_shard_id(lf, (unsigned int)process_event_thread_count);
    analysisd_stamp_queue_in(lf);
    if (analysisd_queue_push_wait(decode_queue_event_output[shard], lf,
                                  cfg_shard_push_wait_ms) != 0) {
        Free_Eventinfo(lf);
        if (!analysisd_shutting_down) {
            analysisd_inc_shard_dropped();
            analysisd_inc_dropped_events();
            analysisd_warn_dropped("decode->shard");
        }
        return -1;
    }

    return 0;
}

int analysisd_enqueue_alert(Eventinfo *lf)
{
    if (!lf) {
        return -1;
    }

    if (!writer_queue_log) {
        return -1;
    }

    analysisd_stamp_queue_in(lf);
    if (analysisd_queue_push_wait(writer_queue_log, lf,
                                  cfg_alerts_push_wait_ms) == 0) {
        return 0;
    }

    if (analysisd_shutting_down) {
        /* Caller still owns lf. */
        return -1;
    }

    /* Brief wait failed: sync write under the same lock as the alert writer. */
    os_mutex_lock(&writer_threads_mutex);
    analysisd_writer_sync_alert(lf);
    os_mutex_unlock(&writer_threads_mutex);

    Free_Eventinfo(lf);
    analysisd_inc_alerts_written();
    return 0;
}

int analysisd_enqueue_statistical(Eventinfo *lf)
{
    if (!lf) {
        return -1;
    }

    if (!writer_queue_statistical) {
        return -1;
    }

    analysisd_stamp_queue_in(lf);
    if (analysisd_queue_push_wait(writer_queue_statistical, lf,
                                  cfg_alerts_push_wait_ms) == 0) {
        return 0;
    }

    if (analysisd_shutting_down) {
        return -1;
    }

    os_mutex_lock(&writer_threads_mutex);
    analysisd_writer_sync_alert(lf);
    os_mutex_unlock(&writer_threads_mutex);

    Free_Eventinfo(lf);
    analysisd_inc_alerts_written();
    return 0;
}

Eventinfo *analysisd_copy_event_for_log(const Eventinfo *lf)
{
    Eventinfo *cpy;
    int i;

    if (!lf) {
        return NULL;
    }

    os_calloc(1, sizeof(Eventinfo), cpy);
    os_calloc(Config.decoder_order_size, sizeof(char *), cpy->fields);

    if (lf->full_log) {
        size_t flen = strlen(lf->full_log);
        size_t loglen = flen + 1;
        size_t dual_size = (2 * loglen) + 1;
        ptrdiff_t log_off = 0;

        if (lf->log) {
            log_off = lf->log - lf->full_log;
        }

        if (lf->log && log_off == 0) {
            /* Syscheck / ossecalert: log aliases the start of full_log. */
            os_strdup(lf->full_log, cpy->full_log);
            cpy->log = cpy->full_log;
        } else if (lf->log && log_off > 0 && (size_t)log_off < dual_size) {
            /* CleanMSG layout: one (2*loglen+1) allocation; log is in the
             * second half (possibly advanced past a date/hostname prefix). */
            os_malloc(dual_size, cpy->full_log);
            memcpy(cpy->full_log, lf->full_log, dual_size);
            cpy->log = cpy->full_log + log_off;
        } else if (lf->log) {
            /* log is not inside full_log — copy both and mark separate. */
            os_strdup(lf->full_log, cpy->full_log);
            os_strdup(lf->log, cpy->log);
            cpy->flags |= EF_SEPARATE_LOG;
        } else {
            os_strdup(lf->full_log, cpy->full_log);
        }
    } else if (lf->log) {
        os_strdup(lf->log, cpy->log);
        cpy->flags |= EF_SEPARATE_LOG;
    }
    if (lf->location) {
        os_strdup(lf->location, cpy->location);
    }
    if (lf->hostname) {
        if (lf->hostname == lf->location && cpy->location) {
            cpy->hostname = cpy->location;
        } else {
            os_strdup(lf->hostname, cpy->hostname);
            cpy->flags |= EF_FREE_HNAME;
        }
    }
    if (lf->program_name) {
        os_strdup(lf->program_name, cpy->program_name);
        cpy->flags |= EF_FREE_PNAME;
    }
    if (lf->action) {
        os_strdup(lf->action, cpy->action);
    }
    if (lf->srcip) {
        os_strdup(lf->srcip, cpy->srcip);
    }
    if (lf->dstip) {
        os_strdup(lf->dstip, cpy->dstip);
    }
    if (lf->srcgeoip) {
        os_strdup(lf->srcgeoip, cpy->srcgeoip);
    }
    if (lf->dstgeoip) {
        os_strdup(lf->dstgeoip, cpy->dstgeoip);
    }
    if (lf->srcport) {
        os_strdup(lf->srcport, cpy->srcport);
    }
    if (lf->dstport) {
        os_strdup(lf->dstport, cpy->dstport);
    }
    if (lf->protocol) {
        os_strdup(lf->protocol, cpy->protocol);
    }
    if (lf->srcuser) {
        os_strdup(lf->srcuser, cpy->srcuser);
    }
    if (lf->dstuser) {
        os_strdup(lf->dstuser, cpy->dstuser);
    }
    if (lf->id) {
        os_strdup(lf->id, cpy->id);
    }
    if (lf->status) {
        os_strdup(lf->status, cpy->status);
    }
    if (lf->command) {
        os_strdup(lf->command, cpy->command);
    }
    if (lf->url) {
        os_strdup(lf->url, cpy->url);
    }
    if (lf->data) {
        os_strdup(lf->data, cpy->data);
    }
    if (lf->systemname) {
        os_strdup(lf->systemname, cpy->systemname);
    }
    if (lf->filename) {
        os_strdup(lf->filename, cpy->filename);
    }
    if (lf->md5_before) {
        os_strdup(lf->md5_before, cpy->md5_before);
    }
    if (lf->md5_after) {
        os_strdup(lf->md5_after, cpy->md5_after);
    }
    if (lf->sha1_before) {
        os_strdup(lf->sha1_before, cpy->sha1_before);
    }
    if (lf->sha1_after) {
        os_strdup(lf->sha1_after, cpy->sha1_after);
    }
    if (lf->sha256_before) {
        os_strdup(lf->sha256_before, cpy->sha256_before);
    }
    if (lf->sha256_after) {
        os_strdup(lf->sha256_after, cpy->sha256_after);
    }
    if (lf->size_before) {
        os_strdup(lf->size_before, cpy->size_before);
    }
    if (lf->size_after) {
        os_strdup(lf->size_after, cpy->size_after);
    }
    if (lf->owner_before) {
        os_strdup(lf->owner_before, cpy->owner_before);
    }
    if (lf->owner_after) {
        os_strdup(lf->owner_after, cpy->owner_after);
    }
    if (lf->gowner_before) {
        os_strdup(lf->gowner_before, cpy->gowner_before);
    }
    if (lf->gowner_after) {
        os_strdup(lf->gowner_after, cpy->gowner_after);
    }

    for (i = 0; i < Config.decoder_order_size; i++) {
        if (lf->fields && lf->fields[i]) {
            os_strdup(lf->fields[i], cpy->fields[i]);
        }
    }

    cpy->perm_before = lf->perm_before;
    cpy->perm_after = lf->perm_after;
    cpy->generated_rule = lf->generated_rule;
    cpy->decoder_info = lf->decoder_info;
    cpy->time = lf->time;
    cpy->day = lf->day;
    cpy->year = lf->year;
    cpy->alert_id = lf->alert_id;
    strncpy(cpy->mon, lf->mon, 3);
    strncpy(cpy->hour, lf->hour, 9);
    cpy->flags |= EF_ASYNC_COPY;

    if (lf->alert_last_events) {
        os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), cpy->alert_last_events);
        for (i = 0; i < MAX_LAST_EVENTS && lf->alert_last_events[i]; i++) {
            os_strdup(lf->alert_last_events[i], cpy->alert_last_events[i]);
        }
        cpy->alert_last_events[i] = NULL;
    }

    return cpy;
}

static void *analysisd_writer_log_thread(void *arg)
{
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        lf = (Eventinfo *)os_queue_pop_ex(writer_queue_log);
        if (!lf) {
            break;
        }

        analysisd_sample_queue_wait(lf, ANALYSISD_QWAIT_ALERTS);

        os_mutex_lock(&writer_threads_mutex);
        analysisd_writer_sync_alert(lf);
        os_mutex_unlock(&writer_threads_mutex);

        Free_Eventinfo(lf);
        analysisd_inc_alerts_written();
    }

    return NULL;
}

static void *analysisd_writer_statistical_thread(void *arg)
{
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        lf = (Eventinfo *)os_queue_pop_ex(writer_queue_statistical);
        if (!lf) {
            break;
        }

        os_mutex_lock(&writer_threads_mutex);
        analysisd_writer_sync_alert(lf);
        os_mutex_unlock(&writer_threads_mutex);

        Free_Eventinfo(lf);
        analysisd_inc_alerts_written();
    }

    return NULL;
}

static void *analysisd_writer_archive_thread(void *arg)
{
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        lf = (Eventinfo *)os_queue_pop_ex(writer_queue_archive);
        if (!lf) {
            break;
        }

        OS_Store(lf);
        if (Config.logall_json) {
            jsonout_output_archive(lf);
        }

        analysisd_inc_archives_written();
        Free_Eventinfo(lf);
    }

    return NULL;
}

static void *analysisd_writer_firewall_thread(void *arg)
{
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        lf = (Eventinfo *)os_queue_pop_ex(writer_queue_firewall);
        if (!lf) {
            break;
        }

        FW_Log(lf);
        analysisd_inc_firewall_written();
        Free_Eventinfo(lf);
    }

    return NULL;
}

static void *analysisd_writer_fts_thread(void *arg)
{
    char *line;
    unsigned int since_flush = 0;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        line = (char *)os_queue_pop_ex(writer_queue_fts);
        if (!line) {
            break;
        }

        FTS_Fprintf(line);
        free(line);
        since_flush++;

        /* Batch fflush so match threads are not blocked on disk sync. */
        if (since_flush >= 64 || os_queue_elements(writer_queue_fts) == 0) {
            FTS_Flush();
            since_flush = 0;
        }
    }

    FTS_Flush();
    return NULL;
}

static void *analysisd_decode_worker_thread(void *arg)
{
    os_queue *input_queue = (os_queue *)arg;
    char *msg;
    char mq_prefix;
    Eventinfo *lf;
    regex_matching decoder_match;

    os_block_worker_signals();
    memset(&decoder_match, 0, sizeof(decoder_match));

    while (!analysisd_shutting_down) {
        msg = (char *)os_queue_pop_ex(input_queue);
        if (!msg) {
            if (analysisd_shutting_down) {
                break;
            }
            continue;
        }

        lf = analysisd_event_alloc();
        Zero_Eventinfo(lf);

        mq_prefix = msg[0];

        if (OS_CleanMSG_ex(msg, lf, time(NULL), 0) < 0) {
            merror(IMSG_ERROR, ARGV0, msg);
            Free_Eventinfo(lf);
            free(msg);
            continue;
        }

        free(msg);

        lf = analysisd_decode_event(lf, mq_prefix, &decoder_match);
        if (!lf) {
            continue;
        }

        analysisd_inc_decoded_events();
        analysisd_push_decoded(lf);
    }

    regex_matching_clear(&decoder_match);
    regex_matching_free_match_data(&decoder_match);
    return NULL;
}

static void *analysisd_decode_syscheck_thread(void *arg)
{
    char *msg;
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();
    SyscheckInit();

    while (!analysisd_shutting_down) {
        msg = (char *)os_queue_pop_ex(decode_queue_syscheck_input);
        if (!msg) {
            if (analysisd_shutting_down) {
                break;
            }
            continue;
        }

        lf = analysisd_event_alloc();
        Zero_Eventinfo(lf);

        if (OS_CleanMSG_ex(msg, lf, time(NULL), 0) < 0) {
            merror(IMSG_ERROR, ARGV0, msg);
            Free_Eventinfo(lf);
            free(msg);
            continue;
        }

        free(msg);

        lf = analysisd_decode_event(lf, SYSCHECK_MQ, NULL);
        if (!lf) {
            continue;
        }

        analysisd_inc_syscheck_decoded_events();
        analysisd_push_decoded(lf);
    }

    return NULL;
}

static void *analysisd_decode_rootcheck_thread(void *arg)
{
    char *msg;
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        msg = (char *)os_queue_pop_ex(decode_queue_rootcheck_input);
        if (!msg) {
            if (analysisd_shutting_down) {
                break;
            }
            continue;
        }

        lf = analysisd_event_alloc();
        Zero_Eventinfo(lf);

        if (OS_CleanMSG_ex(msg, lf, time(NULL), 0) < 0) {
            Free_Eventinfo(lf);
            free(msg);
            continue;
        }

        free(msg);

        lf = analysisd_decode_event(lf, ROOTCHECK_MQ, NULL);
        if (!lf) {
            continue;
        }

        analysisd_inc_rootcheck_decoded_events();
        analysisd_push_decoded(lf);
    }

    return NULL;
}

static void *analysisd_decode_hostinfo_thread(void *arg)
{
    char *msg;
    Eventinfo *lf;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        msg = (char *)os_queue_pop_ex(decode_queue_hostinfo_input);
        if (!msg) {
            if (analysisd_shutting_down) {
                break;
            }
            continue;
        }

        lf = analysisd_event_alloc();
        Zero_Eventinfo(lf);

        if (OS_CleanMSG_ex(msg, lf, time(NULL), 0) < 0) {
            Free_Eventinfo(lf);
            free(msg);
            continue;
        }

        free(msg);

        lf = analysisd_decode_event(lf, HOSTINFO_MQ, NULL);
        if (!lf) {
            continue;
        }

        analysisd_inc_hostinfo_decoded_events();
        analysisd_push_decoded(lf);
    }

    return NULL;
}

static void *analysisd_process_event_thread(void *arg)
{
    int tid = (int)(intptr_t)arg;
    Eventinfo *lf;
    regex_matching rule_match;
    int transferred;

    os_block_worker_signals();

    if (tid < 0 || tid >= process_event_thread_count || !shard_lists) {
        merror("%s: ERROR: invalid process event thread id %d.", ARGV0, tid);
        return NULL;
    }

    analysisd_set_event_list(shard_lists[tid]);
    if (shard_acm_stores) {
        analysisd_set_acm_store(shard_acm_stores[tid]);
    }
    memset(&rule_match, 0, sizeof(rule_match));
    os_regex_set_thread_match(&rule_match);

    while (!analysisd_shutting_down) {
        lf = (Eventinfo *)os_queue_pop_ex(decode_queue_event_output[tid]);
        if (!lf) {
            if (analysisd_shutting_down) {
                break;
            }
            continue;
        }

        analysisd_sample_queue_wait(lf, ANALYSISD_QWAIT_SHARD);
        analysisd_inc_hourly_events();
        transferred = analysisd_analyze_event(lf);
        analysisd_inc_processed_events();
        if (!transferred) {
            analysisd_finish_event(lf);
        }
    }

    analysisd_set_acm_store(NULL);
    os_regex_set_thread_match(NULL);
    regex_matching_clear(&rule_match);
    regex_matching_free_match_data(&rule_match);
    return NULL;
}

static void *analysisd_input_recv_thread(void *arg)
{
    char msg[OS_MAXSTR + 1];
    char *copy;
    int recv_len;
    struct pollfd pfd;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        int fd = (int)pipeline_m_queue;

        if (fd < 0) {
            break;
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        /* Short poll so shutdown flag / closed FD is observed promptly. */
        if (poll(&pfd, 1, 1000) <= 0) {
            continue;
        }

        if (analysisd_shutting_down || (int)pipeline_m_queue < 0) {
            break;
        }

        if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
            continue;
        }

        recv_len = OS_RecvUnix(fd, OS_MAXSTR, msg);
        if (recv_len <= 0) {
            if (analysisd_shutting_down || (int)pipeline_m_queue < 0) {
                break;
            }
            continue;
        }

        if (recv_len < 4) {
            merror(IMSG_ERROR, ARGV0, msg);
            continue;
        }

        copy = strdup(msg);
        if (!copy) {
            merror(MEM_ERROR, ARGV0, errno, strerror(errno));
            continue;
        }

        analysisd_inc_received_events();

        if (analysisd_queue_push_wait(raw_input_queue, copy,
                                      cfg_raw_input_push_wait_ms) != 0) {
            free(copy);
            analysisd_inc_dropped_events();
            analysisd_warn_dropped("raw input");
        }
    }

    return NULL;
}

static void analysisd_close_input_queue(void)
{
    int fd = (int)pipeline_m_queue;

    if (fd < 0) {
        return;
    }

    /* Publish closed state before shutdown/close so the recv loop exits. */
    pipeline_m_queue = -1;
    (void)shutdown(fd, SHUT_RDWR);
    (void)close(fd);
}

static void *analysisd_input_demux_thread(void *arg)
{
    char *copy;
    os_queue *queue;

    (void)arg;
    os_block_worker_signals();

    while (!analysisd_shutting_down) {
        copy = (char *)os_queue_pop_ex(raw_input_queue);
        if (!copy) {
            if (analysisd_shutting_down) {
                break;
            }
            continue;
        }

        queue = analysisd_route_queue(copy[0]);
        if (analysisd_queue_push_wait(queue, copy, cfg_demux_push_wait_ms) != 0) {
            free(copy);
            analysisd_inc_dropped_events();
            analysisd_warn_dropped("demux->decode");
        }
    }

    return NULL;
}

void analysisd_pipeline_request_shutdown(void)
{
    analysisd_shutting_down = 1;
    /* Wake input_recv if it is blocked in poll/recv (producers may already
     * be dead, so no datagrams arrive to unblock a plain recvfrom). */
    analysisd_close_input_queue();
}

void analysisd_log_pipeline_metrics(unsigned int decoded, unsigned int processed,
                                    unsigned int dropped)
{
    unsigned int event_in = 0;
    unsigned int event_out = 0;
    unsigned int alerts_q = 0;
    unsigned int firewall_q = 0;
    int i;

    if (decode_queue_event_input) {
        event_in = os_queue_elements(decode_queue_event_input);
    }
    if (decode_queue_event_output) {
        for (i = 0; i < decode_queue_event_output_count; i++) {
            event_out += os_queue_elements(decode_queue_event_output[i]);
        }
    }
    if (writer_queue_log) {
        alerts_q = os_queue_elements(writer_queue_log);
    }
    if (writer_queue_firewall) {
        firewall_q = os_queue_elements(writer_queue_firewall);
    }

    debug1("%s: pipeline decoded=%u processed=%u dropped=%u "
           "queues(event_in=%u event_out=%u alerts=%u statistical=%u "
           "firewall=%u fts=%u)",
           ARGV0, decoded, processed, dropped, event_in, event_out, alerts_q,
           writer_queue_statistical ? os_queue_elements(writer_queue_statistical) : 0,
           firewall_q,
           writer_queue_fts ? os_queue_elements(writer_queue_fts) : 0);

    if (dropped > 0) {
        analysisd_warn_dropped("metrics interval");
    }
}

static int analysisd_join_thread(pthread_t thread, const char *name)
{
    struct timespec ts;
    int rc;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return pthread_join(thread, NULL);
    }

    ts.tv_sec += ANALYSISD_SHUTDOWN_TIMEOUT;
    rc = pthread_timedjoin_np(thread, NULL, &ts);
    if (rc == ETIMEDOUT) {
        merror("%s: ERROR: timed out joining %s after %d s; aborting to avoid a "
               "half-alive daemon.",
               ARGV0, name, ANALYSISD_SHUTDOWN_TIMEOUT);
        return -1;
    }

    return rc;
}

static void analysisd_free_queued_event(void *ptr)
{
    Free_Eventinfo((Eventinfo *)ptr);
}

static void analysisd_drain_queues(void)
{
    int i;

    /* Defensive: free anything left after workers exit. */
    os_queue_free_data(raw_input_queue, free);
    os_queue_free_data(decode_queue_event_input, free);
    os_queue_free_data(decode_queue_syscheck_input, free);
    os_queue_free_data(decode_queue_rootcheck_input, free);
    os_queue_free_data(decode_queue_hostinfo_input, free);

    if (decode_queue_event_output) {
        for (i = 0; i < decode_queue_event_output_count; i++) {
            os_queue_free_data(decode_queue_event_output[i], analysisd_free_queued_event);
        }
    }

    os_queue_free_data(writer_queue_log, analysisd_free_queued_event);
    os_queue_free_data(writer_queue_statistical, analysisd_free_queued_event);
    os_queue_free_data(writer_queue_archive, analysisd_free_queued_event);
    os_queue_free_data(writer_queue_firewall, analysisd_free_queued_event);
    os_queue_free_data(writer_queue_fts, free);
}

void analysisd_pipeline_shutdown(void)
{
    int i;
    char name[64];
    int join_failed = 0;

    analysisd_shutting_down = 1;
    analysisd_state_shutdown();

    /* Stage 1: stop accepting new messages, then drain decode input. */
    analysisd_close_input_queue();

    if (analysisd_join_thread(input_recv_thread_id, "input recv thread") != 0) {
        join_failed = 1;
    }

    os_queue_shutdown(raw_input_queue);
    for (i = 0; i < input_demux_thread_count; i++) {
        snprintf(name, sizeof(name), "input demux thread %d", i);
        if (analysisd_join_thread(input_demux_threads[i], name) != 0) {
            join_failed = 1;
        }
    }

    os_queue_shutdown(decode_queue_event_input);
    os_queue_shutdown(decode_queue_syscheck_input);
    os_queue_shutdown(decode_queue_rootcheck_input);
    os_queue_shutdown(decode_queue_hostinfo_input);

    for (i = 0; i < decode_event_thread_count; i++) {
        snprintf(name, sizeof(name), "decode event thread %d", i);
        if (analysisd_join_thread(decode_event_threads[i], name) != 0) {
            join_failed = 1;
        }
    }
    for (i = 0; i < decode_syscheck_thread_count; i++) {
        snprintf(name, sizeof(name), "decode syscheck thread %d", i);
        if (analysisd_join_thread(decode_syscheck_threads[i], name) != 0) {
            join_failed = 1;
        }
    }
    for (i = 0; i < decode_rootcheck_thread_count; i++) {
        snprintf(name, sizeof(name), "decode rootcheck thread %d", i);
        if (analysisd_join_thread(decode_rootcheck_threads[i], name) != 0) {
            join_failed = 1;
        }
    }
    for (i = 0; i < decode_hostinfo_thread_count; i++) {
        snprintf(name, sizeof(name), "decode hostinfo thread %d", i);
        if (analysisd_join_thread(decode_hostinfo_threads[i], name) != 0) {
            join_failed = 1;
        }
    }

    /* Stage 2: finish rule matching on decoded events (per-shard queues). */
    if (decode_queue_event_output) {
        for (i = 0; i < decode_queue_event_output_count; i++) {
            os_queue_shutdown(decode_queue_event_output[i]);
        }
    }

    for (i = 0; i < process_event_thread_count; i++) {
        snprintf(name, sizeof(name), "process event thread %d", i);
        if (analysisd_join_thread(process_event_threads[i], name) != 0) {
            join_failed = 1;
        }
    }

    /* Stage 3: flush alert/statistical/archive/firewall/FTS writers. */
    os_queue_shutdown(writer_queue_log);
    os_queue_shutdown(writer_queue_statistical);
    os_queue_shutdown(writer_queue_archive);
    os_queue_shutdown(writer_queue_firewall);
    os_queue_shutdown(writer_queue_fts);

    if (analysisd_join_thread(writer_log_thread_id, "alert writer") != 0) {
        join_failed = 1;
    }
    if (analysisd_join_thread(writer_statistical_thread_id,
                              "statistical writer") != 0) {
        join_failed = 1;
    }
    if (analysisd_join_thread(writer_archive_thread_id, "archive writer") != 0) {
        join_failed = 1;
    }
    if (analysisd_join_thread(writer_firewall_thread_id, "firewall writer") != 0) {
        join_failed = 1;
    }
    if (analysisd_join_thread(writer_fts_thread_id, "FTS writer") != 0) {
        join_failed = 1;
    }
    if (analysisd_join_thread(state_thread_id, "state thread") != 0) {
        join_failed = 1;
    }

    analysisd_drain_queues();

    if (shard_lists) {
        for (i = 0; i < process_event_thread_count; i++) {
            OS_EventList_Destroy(shard_lists[i]);
            shard_lists[i] = NULL;
        }
        free(shard_lists);
        shard_lists = NULL;
    }

    if (shard_acm_stores) {
        for (i = 0; i < process_event_thread_count; i++) {
            Accumulate_DestroyStore(shard_acm_stores[i]);
            shard_acm_stores[i] = NULL;
        }
        free(shard_acm_stores);
        shard_acm_stores = NULL;
    }

    free(decode_event_threads);
    free(decode_syscheck_threads);
    free(decode_rootcheck_threads);
    free(decode_hostinfo_threads);
    free(process_event_threads);
    free(input_demux_threads);
    input_demux_threads = NULL;
    input_demux_thread_count = 0;

    analysisd_destroy_queues();

    if (join_failed) {
        DeletePID(ARGV0);
        _exit(1);
    }
}

void analysisd_pipeline_run(int m_queue)
{
    int i;

    pipeline_m_queue = m_queue;

    cfg_event_threads = analysisd_resolve_threads("event_threads");
    cfg_syscheck_threads = analysisd_resolve_threads("syscheck_threads");
    cfg_rootcheck_threads = analysisd_resolve_threads("rootcheck_threads");
    cfg_hostinfo_threads = analysisd_resolve_threads("hostinfo_threads");
    cfg_rule_matching_threads = analysisd_resolve_threads("rule_matching_threads");
    cfg_input_demux_threads =
        getDefine_Int("analysisd", "input_demux_threads", 1,
                      ANALYSISD_INPUT_DEMUX_THREADS_MAX);

    cfg_decode_event_queue_size = analysisd_resolve_queue_size("decode_event_queue_size");
    cfg_raw_input_queue_size = analysisd_resolve_queue_size("raw_input_queue_size");
    cfg_decode_syscheck_queue_size = analysisd_resolve_queue_size("decode_syscheck_queue_size");
    cfg_decode_rootcheck_queue_size = analysisd_resolve_queue_size("decode_rootcheck_queue_size");
    cfg_decode_hostinfo_queue_size = analysisd_resolve_queue_size("decode_hostinfo_queue_size");
    cfg_decode_output_queue_size = analysisd_resolve_queue_size("decode_output_queue_size");
    cfg_alerts_queue_size = analysisd_resolve_queue_size("alerts_queue_size");
    cfg_statistical_queue_size = analysisd_resolve_queue_size("statistical_queue_size");
    cfg_archives_queue_size = analysisd_resolve_queue_size("archives_queue_size");
    cfg_firewall_queue_size = analysisd_resolve_queue_size("firewall_queue_size");
    cfg_fts_queue_size = analysisd_resolve_queue_size("fts_queue_size");

    cfg_raw_input_push_wait_ms =
        analysisd_resolve_push_wait_ms("raw_input_push_wait_ms", 25);
    cfg_demux_push_wait_ms =
        analysisd_resolve_push_wait_ms("demux_push_wait_ms", 50);
    cfg_shard_push_wait_ms =
        analysisd_resolve_push_wait_ms("shard_push_wait_ms", 75);
    cfg_alerts_push_wait_ms =
        analysisd_resolve_push_wait_ms("alerts_push_wait_ms", 100);

    decode_event_thread_count = cfg_event_threads;
    decode_syscheck_thread_count = cfg_syscheck_threads;
    decode_rootcheck_thread_count = cfg_rootcheck_threads;
    decode_hostinfo_thread_count = cfg_hostinfo_threads;
    process_event_thread_count = cfg_rule_matching_threads;
    input_demux_thread_count = cfg_input_demux_threads;

    analysisd_state_init();
    analysisd_init_queues();

    os_calloc((size_t)process_event_thread_count, sizeof(EventList *), shard_lists);
    os_calloc((size_t)process_event_thread_count, sizeof(OSHash *), shard_acm_stores);
    for (i = 0; i < process_event_thread_count; i++) {
        shard_lists[i] = OS_EventList_Create(Config.memorysize);
        shard_acm_stores[i] = Accumulate_CreateStore();
        if (!shard_acm_stores[i]) {
            ErrorExit("%s: ERROR: Unable to create per-shard Accumulate store.", ARGV0);
        }
    }

    os_calloc((size_t)decode_event_thread_count, sizeof(pthread_t), decode_event_threads);
    os_calloc((size_t)decode_syscheck_thread_count, sizeof(pthread_t), decode_syscheck_threads);
    os_calloc((size_t)decode_rootcheck_thread_count, sizeof(pthread_t), decode_rootcheck_threads);
    os_calloc((size_t)decode_hostinfo_thread_count, sizeof(pthread_t), decode_hostinfo_threads);
    os_calloc((size_t)process_event_thread_count, sizeof(pthread_t), process_event_threads);
    os_calloc((size_t)input_demux_thread_count, sizeof(pthread_t), input_demux_threads);

    CreateThreadJoinable(&writer_log_thread_id, analysisd_writer_log_thread, NULL);
    CreateThreadJoinable(&writer_statistical_thread_id,
                         analysisd_writer_statistical_thread, NULL);
    CreateThreadJoinable(&writer_archive_thread_id, analysisd_writer_archive_thread, NULL);
    CreateThreadJoinable(&writer_firewall_thread_id, analysisd_writer_firewall_thread, NULL);
    CreateThreadJoinable(&writer_fts_thread_id, analysisd_writer_fts_thread, NULL);
    CreateThreadJoinable(&state_thread_id, analysisd_state_thread, NULL);

    for (i = 0; i < decode_syscheck_thread_count; i++) {
        CreateThreadJoinable(&decode_syscheck_threads[i], analysisd_decode_syscheck_thread, NULL);
    }
    for (i = 0; i < decode_rootcheck_thread_count; i++) {
        CreateThreadJoinable(&decode_rootcheck_threads[i], analysisd_decode_rootcheck_thread, NULL);
    }
    for (i = 0; i < decode_hostinfo_thread_count; i++) {
        CreateThreadJoinable(&decode_hostinfo_threads[i], analysisd_decode_hostinfo_thread, NULL);
    }
    for (i = 0; i < decode_event_thread_count; i++) {
        CreateThreadJoinable(&decode_event_threads[i], analysisd_decode_worker_thread,
                             decode_queue_event_input);
    }
    for (i = 0; i < process_event_thread_count; i++) {
        CreateThreadJoinable(&process_event_threads[i], analysisd_process_event_thread,
                             (void *)(intptr_t)i);
    }

    CreateThreadJoinable(&input_recv_thread_id, analysisd_input_recv_thread, NULL);
    for (i = 0; i < input_demux_thread_count; i++) {
        CreateThreadJoinable(&input_demux_threads[i], analysisd_input_demux_thread, NULL);
    }

    verbose("%s: INFO: Multi-threaded analysisd pipeline started "
            "(event_threads=%d syscheck=%d rootcheck=%d hostinfo=%d "
            "rule_matching=%d shards=%d input_demux=%d).",
            ARGV0, decode_event_thread_count, decode_syscheck_thread_count,
            decode_rootcheck_thread_count, decode_hostinfo_thread_count,
            process_event_thread_count, process_event_thread_count,
            input_demux_thread_count);
    if (process_event_thread_count > 1) {
        verbose("%s: INFO: Correlation shards=%d: Search_LastEvents is "
                "per-location; cross-agent frequency needs if_matched_sid "
                "or if_matched_group.",
                ARGV0, process_event_thread_count);
    }

    while (!analysisd_shutting_down) {
        sleep(1);
    }

    verbose("%s: INFO: Shutting down analysisd pipeline.", ARGV0);
    analysisd_pipeline_shutdown();
}

#endif /* !WIN32 */
