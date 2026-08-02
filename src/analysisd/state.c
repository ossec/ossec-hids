/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "state.h"
#include "pipeline.h"
#include "queue_op.h"

extern os_queue *decode_queue_event_input;
extern os_queue *decode_queue_syscheck_input;
extern os_queue *decode_queue_rootcheck_input;
extern os_queue *decode_queue_hostinfo_input;
extern os_queue **decode_queue_event_output;
extern int decode_queue_event_output_count;
extern os_queue *raw_input_queue;
extern os_queue *writer_queue_log;
extern os_queue *writer_queue_statistical;
extern os_queue *writer_queue_archive;
extern os_queue *writer_queue_firewall;
extern os_queue *writer_queue_fts;

static volatile int state_shutdown = 0;
static int state_interval = 5;

static unsigned int s_received_events = 0;
static unsigned int s_decoded_events = 0;
static unsigned int s_processed_events = 0;
static unsigned int s_dropped_events = 0;
static unsigned int s_shard_dropped = 0;
static unsigned int s_alerts_dropped = 0;
static unsigned int s_syscheck_decoded = 0;
static unsigned int s_rootcheck_decoded = 0;
static unsigned int s_hostinfo_decoded = 0;
static unsigned int s_alerts_written = 0;
static unsigned int s_archives_written = 0;
static unsigned int s_firewall_written = 0;
static unsigned int s_archives_dropped = 0;

/* EPDS: events processed during last state_interval window. */
static unsigned int s_prev_processed = 0;
static unsigned int s_prev_dropped = 0;
static unsigned int s_prev_shard_dropped = 0;
static unsigned int s_prev_alerts_dropped = 0;
static unsigned int s_prev_archives_dropped = 0;
static unsigned int s_dropped_delta = 0;
static unsigned int s_shard_dropped_delta = 0;
static unsigned int s_alerts_dropped_delta = 0;
static unsigned int s_archives_dropped_delta = 0;
static double s_epds = 0.0;
static double s_alerts_q_wait_ms_est = 0.0;

/* Circular sample buffers for enqueue→dequeue wait (microseconds). */
#define ANALYSISD_QWAIT_SAMPLES 1024
static unsigned int s_shard_wait_us[ANALYSISD_QWAIT_SAMPLES];
static unsigned int s_alerts_wait_us[ANALYSISD_QWAIT_SAMPLES];
static unsigned int s_shard_wait_idx = 0;
static unsigned int s_alerts_wait_idx = 0;
static unsigned int s_shard_wait_count = 0;
static unsigned int s_alerts_wait_count = 0;
static unsigned int s_shard_wait_p50_us = 0;
static unsigned int s_shard_wait_p99_us = 0;
static unsigned int s_alerts_wait_p50_us = 0;
static unsigned int s_alerts_wait_p99_us = 0;

void analysisd_state_init(void)
{
    state_shutdown = 0;
    state_interval = getDefine_Int("analysisd", "state_interval", 0, 86400);
}

void analysisd_state_shutdown(void)
{
    state_shutdown = 1;
}

static void analysisd_inc_counter(unsigned int *counter)
{
    __sync_add_and_fetch(counter, 1);
}

static unsigned int analysisd_get_counter(unsigned int *counter)
{
    return __sync_fetch_and_add(counter, 0);
}

void analysisd_inc_decoded_events(void) { analysisd_inc_counter(&s_decoded_events); }
void analysisd_inc_processed_events(void) { analysisd_inc_counter(&s_processed_events); }
void analysisd_inc_received_events(void) { analysisd_inc_counter(&s_received_events); }
void analysisd_inc_dropped_events(void) { analysisd_inc_counter(&s_dropped_events); }
void analysisd_inc_shard_dropped(void) { analysisd_inc_counter(&s_shard_dropped); }
void analysisd_inc_alerts_dropped(void) { analysisd_inc_counter(&s_alerts_dropped); }
void analysisd_inc_syscheck_decoded_events(void) { analysisd_inc_counter(&s_syscheck_decoded); }
void analysisd_inc_rootcheck_decoded_events(void) { analysisd_inc_counter(&s_rootcheck_decoded); }
void analysisd_inc_hostinfo_decoded_events(void) { analysisd_inc_counter(&s_hostinfo_decoded); }
void analysisd_inc_alerts_written(void) { analysisd_inc_counter(&s_alerts_written); }
void analysisd_inc_archives_written(void) { analysisd_inc_counter(&s_archives_written); }
void analysisd_inc_firewall_written(void) { analysisd_inc_counter(&s_firewall_written); }
void analysisd_inc_archives_dropped(void) { analysisd_inc_counter(&s_archives_dropped); }

unsigned int analysisd_get_dropped_events(void) { return analysisd_get_counter(&s_dropped_events); }
unsigned int analysisd_get_shard_dropped(void) { return analysisd_get_counter(&s_shard_dropped); }
unsigned int analysisd_get_alerts_dropped(void) { return analysisd_get_counter(&s_alerts_dropped); }
unsigned int analysisd_get_received_events(void) { return analysisd_get_counter(&s_received_events); }
unsigned int analysisd_get_decoded_events(void) { return analysisd_get_counter(&s_decoded_events); }
unsigned int analysisd_get_processed_events(void) { return analysisd_get_counter(&s_processed_events); }
unsigned int analysisd_get_syscheck_decoded_events(void) { return analysisd_get_counter(&s_syscheck_decoded); }
unsigned int analysisd_get_rootcheck_decoded_events(void) { return analysisd_get_counter(&s_rootcheck_decoded); }
unsigned int analysisd_get_hostinfo_decoded_events(void) { return analysisd_get_counter(&s_hostinfo_decoded); }
unsigned int analysisd_get_alerts_written(void) { return analysisd_get_counter(&s_alerts_written); }
unsigned int analysisd_get_archives_written(void) { return analysisd_get_counter(&s_archives_written); }
unsigned int analysisd_get_firewall_written(void) { return analysisd_get_counter(&s_firewall_written); }
unsigned int analysisd_get_archives_dropped(void) { return analysisd_get_counter(&s_archives_dropped); }

void analysisd_stamp_queue_in(Eventinfo *lf)
{
    if (!lf) {
        return;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &lf->queue_in_time) != 0) {
        lf->queue_in_time.tv_sec = 0;
        lf->queue_in_time.tv_nsec = 0;
    }
}

void analysisd_sample_queue_wait(Eventinfo *lf, int which)
{
    struct timespec now;
    unsigned long long us;
    unsigned int *buf;
    unsigned int *idx;
    unsigned int *count;
    unsigned int slot;

    if (!lf || (lf->queue_in_time.tv_sec == 0 && lf->queue_in_time.tv_nsec == 0)) {
        return;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return;
    }

    us = (unsigned long long)(now.tv_sec - lf->queue_in_time.tv_sec) * 1000000ULL;
    if (now.tv_nsec >= lf->queue_in_time.tv_nsec) {
        us += (unsigned long long)(now.tv_nsec - lf->queue_in_time.tv_nsec) / 1000ULL;
    } else {
        us -= 1000000ULL;
        us += (unsigned long long)(now.tv_nsec + 1000000000L - lf->queue_in_time.tv_nsec) / 1000ULL;
    }

    if (us > 0xffffffffULL) {
        us = 0xffffffffULL;
    }

    if (which == ANALYSISD_QWAIT_ALERTS) {
        buf = s_alerts_wait_us;
        idx = &s_alerts_wait_idx;
        count = &s_alerts_wait_count;
    } else {
        buf = s_shard_wait_us;
        idx = &s_shard_wait_idx;
        count = &s_shard_wait_count;
    }

    slot = __sync_fetch_and_add(idx, 1) % ANALYSISD_QWAIT_SAMPLES;
    buf[slot] = (unsigned int)us;
    __sync_add_and_fetch(count, 1);
}

static int analysisd_cmp_uint(const void *a, const void *b)
{
    unsigned int ua = *(const unsigned int *)a;
    unsigned int ub = *(const unsigned int *)b;

    if (ua < ub) {
        return -1;
    }
    if (ua > ub) {
        return 1;
    }
    return 0;
}

static void analysisd_percentile_us(const unsigned int *src, unsigned int filled,
                                    unsigned int *p50, unsigned int *p99)
{
    unsigned int tmp[ANALYSISD_QWAIT_SAMPLES];
    unsigned int n;
    unsigned int i50;
    unsigned int i99;

    *p50 = 0;
    *p99 = 0;
    if (filled == 0) {
        return;
    }

    n = filled < ANALYSISD_QWAIT_SAMPLES ? filled : ANALYSISD_QWAIT_SAMPLES;
    memcpy(tmp, src, n * sizeof(unsigned int));
    qsort(tmp, n, sizeof(unsigned int), analysisd_cmp_uint);

    i50 = (n * 50) / 100;
    i99 = (n * 99) / 100;
    if (i50 >= n) {
        i50 = n - 1;
    }
    if (i99 >= n) {
        i99 = n - 1;
    }
    *p50 = tmp[i50];
    *p99 = tmp[i99];
}

static float analysisd_queue_usage(const os_queue *queue)
{
    unsigned int elements;
    unsigned int capacity;

    if (!queue || queue->size < 2) {
        return 0.0f;
    }

    elements = os_queue_elements(queue);
    capacity = (unsigned int)(queue->size - 1);
    if (capacity == 0) {
        return 0.0f;
    }

    return (float)elements / (float)capacity;
}

static unsigned int analysisd_queue_capacity(const os_queue *queue)
{
    if (!queue || queue->size < 2) {
        return 0;
    }

    return (unsigned int)(queue->size - 1);
}

static float analysisd_sharded_queue_usage(void)
{
    int i;
    unsigned long elements = 0;
    unsigned long capacity = 0;

    if (!decode_queue_event_output || decode_queue_event_output_count <= 0) {
        return 0.0f;
    }

    for (i = 0; i < decode_queue_event_output_count; i++) {
        elements += os_queue_elements(decode_queue_event_output[i]);
        capacity += analysisd_queue_capacity(decode_queue_event_output[i]);
    }

    if (capacity == 0) {
        return 0.0f;
    }

    return (float)elements / (float)capacity;
}

static unsigned int analysisd_sharded_queue_capacity(void)
{
    int i;
    unsigned int capacity = 0;

    if (!decode_queue_event_output || decode_queue_event_output_count <= 0) {
        return 0;
    }

    for (i = 0; i < decode_queue_event_output_count; i++) {
        capacity += analysisd_queue_capacity(decode_queue_event_output[i]);
    }

    return capacity;
}

/* Unsigned wraparound preserves the modular delta across UINT_MAX. */
static unsigned int analysisd_delta_since(unsigned int current, unsigned int prev)
{
    return current - prev;
}

int analysisd_write_state(void)
{
    FILE *fp;
    char path[PATH_MAX - 8];
    char path_temp[PATH_MAX + 1];
    unsigned int dropped;
    unsigned int processed;
    unsigned int processed_delta;
    unsigned int shard_dropped;
    unsigned int alerts_dropped;
    unsigned int archives_dropped;
    unsigned int alerts_depth;
    unsigned int shard_n;
    unsigned int alerts_n;

    if (!strcmp(__local_name, "unset")) {
        merror("%s: At analysisd_write_state(): __local_name is unset.", ARGV0);
        return -1;
    }

    snprintf(path, sizeof(path), OS_PIDFILE "/%s.state", __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    fp = fopen(path_temp, "w");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, path_temp, errno, strerror(errno));
        return -1;
    }

    dropped = analysisd_get_dropped_events();
    processed = analysisd_get_processed_events();
    shard_dropped = analysisd_get_shard_dropped();
    alerts_dropped = analysisd_get_alerts_dropped();
    archives_dropped = analysisd_get_archives_dropped();

    /* Compute deltas from committed baselines; update baselines only after
     * the state file is persisted successfully below. */
    processed_delta = analysisd_delta_since(processed, s_prev_processed);
    s_dropped_delta = analysisd_delta_since(dropped, s_prev_dropped);
    s_shard_dropped_delta = analysisd_delta_since(shard_dropped, s_prev_shard_dropped);
    s_alerts_dropped_delta = analysisd_delta_since(alerts_dropped, s_prev_alerts_dropped);
    s_archives_dropped_delta = analysisd_delta_since(archives_dropped,
                                                     s_prev_archives_dropped);
    if (state_interval > 0) {
        s_epds = (double)processed_delta / (double)state_interval;
    } else {
        s_epds = 0.0;
    }

    alerts_depth = 0;
    if (writer_queue_log) {
        alerts_depth = os_queue_elements(writer_queue_log);
    }
    if (s_epds > 0.0) {
        s_alerts_q_wait_ms_est = ((double)alerts_depth / s_epds) * 1000.0;
    } else {
        s_alerts_q_wait_ms_est = 0.0;
    }

    shard_n = analysisd_get_counter(&s_shard_wait_count);
    alerts_n = analysisd_get_counter(&s_alerts_wait_count);
    analysisd_percentile_us(s_shard_wait_us, shard_n,
                            &s_shard_wait_p50_us, &s_shard_wait_p99_us);
    analysisd_percentile_us(s_alerts_wait_us, alerts_n,
                            &s_alerts_wait_p50_us, &s_alerts_wait_p99_us);

    fprintf(fp,
            "# State file for %s (pipeline metrics)\n"
            "\n"
            "# Events accepted from the Unix MQ (before raw queue)\n"
            "events_received='%u'\n"
            "\n"
            "# Events decoded (general decode workers)\n"
            "events_decoded='%u'\n"
            "\n"
            "# Syscheck events decoded\n"
            "syscheck_events_decoded='%u'\n"
            "\n"
            "# Rootcheck events decoded\n"
            "rootcheck_events_decoded='%u'\n"
            "\n"
            "# Hostinfo events decoded\n"
            "hostinfo_events_decoded='%u'\n"
            "\n"
            "# Events processed (rule matching)\n"
            "events_processed='%u'\n"
            "\n"
            "# Events dropped (decode input queue full)\n"
            "events_dropped='%u'\n"
            "\n"
            "# Events dropped since last state write\n"
            "events_dropped_delta='%u'\n"
            "\n"
            "# Events dropped (decode->shard output timed out)\n"
            "events_dropped_shard='%u'\n"
            "\n"
            "# Shard drops since last state write\n"
            "events_dropped_shard_delta='%u'\n"
            "\n"
            "# Alerts dropped (alert queue timed out without sync fallback write)\n"
            "alerts_dropped='%u'\n"
            "\n"
            "# Alerts dropped since last state write\n"
            "alerts_dropped_delta='%u'\n"
            "\n"
            "# Archives dropped (archive writer queue full; logall is best-effort)\n"
            "archives_dropped='%u'\n"
            "\n"
            "# Archives dropped since last state write\n"
            "archives_dropped_delta='%u'\n"
            "\n"
            "# Alerts written\n"
            "alerts_written='%u'\n"
            "\n"
            "# Archives written\n"
            "archives_written='%u'\n"
            "\n"
            "# Firewall events written\n"
            "firewall_written='%u'\n"
            "\n"
            "# Raw input queue (recv -> demux)\n"
            "raw_input_queue_usage='%.2f'\n"
            "raw_input_queue_size='%u'\n"
            "\n"
            "# Decode event input queue\n"
            "event_queue_usage='%.2f'\n"
            "event_queue_size='%u'\n"
            "\n"
            "# Syscheck decode input queue\n"
            "syscheck_queue_usage='%.2f'\n"
            "syscheck_queue_size='%u'\n"
            "\n"
            "# Rootcheck decode input queue\n"
            "rootcheck_queue_usage='%.2f'\n"
            "rootcheck_queue_size='%u'\n"
            "\n"
            "# Hostinfo decode input queue\n"
            "hostinfo_queue_usage='%.2f'\n"
            "hostinfo_queue_size='%u'\n"
            "\n"
            "# Rule matching (decode output) queue\n"
            "rule_matching_queue_usage='%.2f'\n"
            "rule_matching_queue_size='%u'\n"
            "\n"
            "# Alerts writer queue\n"
            "alerts_queue_usage='%.2f'\n"
            "alerts_queue_size='%u'\n"
            "\n"
            "# Statistical (Check_Hour) writer queue\n"
            "statistical_queue_usage='%.2f'\n"
            "statistical_queue_size='%u'\n"
            "\n"
            "# Archives writer queue\n"
            "archives_queue_usage='%.2f'\n"
            "archives_queue_size='%u'\n"
            "\n"
            "# Firewall writer queue\n"
            "firewall_queue_usage='%.2f'\n"
            "firewall_queue_size='%u'\n"
            "\n"
            "# FTS writer queue\n"
            "fts_queue_usage='%.2f'\n"
            "fts_queue_size='%u'\n"
            "\n"
            "# Events processed per second (over state_interval)\n"
            "events_processed_per_second='%.2f'\n"
            "\n"
            "# Estimated alerts queue wait (elements / epds), milliseconds\n"
            "alerts_queue_wait_ms_est='%.2f'\n"
            "\n"
            "# Sampled queue wait percentiles (microseconds)\n"
            "rule_matching_queue_wait_p50_us='%u'\n"
            "rule_matching_queue_wait_p99_us='%u'\n"
            "alerts_queue_wait_p50_us='%u'\n"
            "alerts_queue_wait_p99_us='%u'\n",
            __local_name,
            analysisd_get_received_events(),
            analysisd_get_decoded_events(),
            analysisd_get_syscheck_decoded_events(),
            analysisd_get_rootcheck_decoded_events(),
            analysisd_get_hostinfo_decoded_events(),
            analysisd_get_processed_events(),
            dropped,
            s_dropped_delta,
            analysisd_get_shard_dropped(),
            s_shard_dropped_delta,
            analysisd_get_alerts_dropped(),
            s_alerts_dropped_delta,
            analysisd_get_archives_dropped(),
            s_archives_dropped_delta,
            analysisd_get_alerts_written(),
            analysisd_get_archives_written(),
            analysisd_get_firewall_written(),
            analysisd_queue_usage(raw_input_queue),
            analysisd_queue_capacity(raw_input_queue),
            analysisd_queue_usage(decode_queue_event_input),
            analysisd_queue_capacity(decode_queue_event_input),
            analysisd_queue_usage(decode_queue_syscheck_input),
            analysisd_queue_capacity(decode_queue_syscheck_input),
            analysisd_queue_usage(decode_queue_rootcheck_input),
            analysisd_queue_capacity(decode_queue_rootcheck_input),
            analysisd_queue_usage(decode_queue_hostinfo_input),
            analysisd_queue_capacity(decode_queue_hostinfo_input),
            analysisd_sharded_queue_usage(),
            analysisd_sharded_queue_capacity(),
            analysisd_queue_usage(writer_queue_log),
            analysisd_queue_capacity(writer_queue_log),
            analysisd_queue_usage(writer_queue_statistical),
            analysisd_queue_capacity(writer_queue_statistical),
            analysisd_queue_usage(writer_queue_archive),
            analysisd_queue_capacity(writer_queue_archive),
            analysisd_queue_usage(writer_queue_firewall),
            analysisd_queue_capacity(writer_queue_firewall),
            analysisd_queue_usage(writer_queue_fts),
            analysisd_queue_capacity(writer_queue_fts),
            s_epds,
            s_alerts_q_wait_ms_est,
            s_shard_wait_p50_us,
            s_shard_wait_p99_us,
            s_alerts_wait_p50_us,
            s_alerts_wait_p99_us);

    fclose(fp);

    if (rename(path_temp, path) < 0) {
        merror("%s: ERROR: Unable to update state file '%s': %s",
               ARGV0, path, strerror(errno));
        unlink(path_temp);
        return -1;
    }

    s_prev_processed = processed;
    s_prev_dropped = dropped;
    s_prev_shard_dropped = shard_dropped;
    s_prev_alerts_dropped = alerts_dropped;
    s_prev_archives_dropped = archives_dropped;

    analysisd_log_pipeline_metrics(analysisd_get_decoded_events(),
                                   analysisd_get_processed_events(),
                                   dropped);
    return 0;
}

void *analysisd_state_thread(void *arg)
{
    int i;

    (void)arg;

    os_block_worker_signals();

    if (!state_interval) {
        verbose("%s: INFO: analysisd state file disabled (state_interval=0).", ARGV0);
        while (!state_shutdown) {
            sleep(1);
        }
        return NULL;
    }

    while (!state_shutdown) {
        analysisd_write_state();

        for (i = 0; i < state_interval && !state_shutdown; i++) {
            sleep(1);
        }
    }

    return NULL;
}

#endif /* !WIN32 */
