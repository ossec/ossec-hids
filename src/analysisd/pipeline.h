/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ANALYSISD_PIPELINE_H
#define ANALYSISD_PIPELINE_H

#ifndef WIN32

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "queue_op.h"

#define ANALYSISD_SHUTDOWN_TIMEOUT 30

Eventinfo *analysisd_event_alloc(void);
void analysisd_set_time_context(Eventinfo *lf);
int analysisd_handle_hour_rollover(Eventinfo *lf);
Eventinfo *analysisd_decode_event(Eventinfo *lf, char mq_prefix, regex_matching *decoder_match);
/* Returns 1 if lf ownership transferred to a writer (caller must not free). */
int analysisd_analyze_event(Eventinfo *lf);
void analysisd_finish_event(Eventinfo *lf);

Eventinfo *analysisd_copy_event_for_log(const Eventinfo *lf);
/* Enqueue alert copy with timed wait; sync-write fallback under writer mutex. */
int analysisd_enqueue_alert(Eventinfo *lf);
/* Enqueue Check_Hour / statistical alert; timed wait + sync OS_Log fallback. */
int analysisd_enqueue_statistical(Eventinfo *lf);

/* Ticket-style alert IDs for async writers (replaces sole reliance on ftell). */
long analysisd_claim_alert_id(void);

void analysisd_pipeline_run(int m_queue);
void analysisd_pipeline_shutdown(void);
void analysisd_pipeline_request_shutdown(void);
void analysisd_log_pipeline_metrics(unsigned int decoded, unsigned int processed,
                                    unsigned int dropped);

void analysisd_init_queues(void);
void analysisd_destroy_queues(void);

/* Exported for analysisd_stages.c / state.c / fts.c */
extern os_queue *raw_input_queue;
extern os_queue *writer_queue_log;
extern os_queue *writer_queue_statistical;
extern os_queue *writer_queue_archive;
extern os_queue *writer_queue_firewall;
extern os_queue *writer_queue_fts;
extern os_queue **decode_queue_event_output;
extern int decode_queue_event_output_count;

#endif /* !WIN32 */

#endif /* ANALYSISD_PIPELINE_H */
