/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ANALYSISD_STATE_H
#define ANALYSISD_STATE_H

#ifndef WIN32

#include "eventinfo.h"

/* Queue-wait sample channels for analysisd_sample_queue_wait(). */
#define ANALYSISD_QWAIT_SHARD  0
#define ANALYSISD_QWAIT_ALERTS 1

void analysisd_state_init(void);
void analysisd_state_shutdown(void);
void *analysisd_state_thread(void *arg);
int analysisd_write_state(void);

void analysisd_inc_decoded_events(void);
void analysisd_inc_processed_events(void);
void analysisd_inc_received_events(void);
void analysisd_inc_dropped_events(void);
void analysisd_inc_shard_dropped(void);
void analysisd_inc_alerts_dropped(void);
void analysisd_inc_syscheck_decoded_events(void);
void analysisd_inc_rootcheck_decoded_events(void);
void analysisd_inc_hostinfo_decoded_events(void);
void analysisd_inc_alerts_written(void);
void analysisd_inc_archives_written(void);
void analysisd_inc_firewall_written(void);
void analysisd_inc_archives_dropped(void);

unsigned int analysisd_get_dropped_events(void);
unsigned int analysisd_get_shard_dropped(void);
unsigned int analysisd_get_alerts_dropped(void);
unsigned int analysisd_get_received_events(void);
unsigned int analysisd_get_decoded_events(void);
unsigned int analysisd_get_processed_events(void);
unsigned int analysisd_get_syscheck_decoded_events(void);
unsigned int analysisd_get_rootcheck_decoded_events(void);
unsigned int analysisd_get_hostinfo_decoded_events(void);
unsigned int analysisd_get_alerts_written(void);
unsigned int analysisd_get_archives_written(void);
unsigned int analysisd_get_firewall_written(void);
unsigned int analysisd_get_archives_dropped(void);

void analysisd_stamp_queue_in(Eventinfo *lf);
void analysisd_sample_queue_wait(Eventinfo *lf, int which);

#endif /* !WIN32 */

#endif /* ANALYSISD_STATE_H */
