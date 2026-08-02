/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ANALYSISD_CORRELATION_SHARD_H
#define ANALYSISD_CORRELATION_SHARD_H

#include "eventinfo.h"

#ifndef WIN32

/* Hash location (or hostname) into [0, nshards). Exceeds nested's single
 * contended EventList by giving each process worker a private list. */
unsigned int analysisd_shard_id(const Eventinfo *lf, unsigned int nshards);

EventList *OS_EventList_Create(int maxsize);
void OS_EventList_Destroy(EventList *list);
void analysisd_set_event_list(EventList *list);
EventList *analysisd_get_event_list(void);

/* Accumulate store TLS setters live in accumulator.h; pipeline includes both. */

#endif /* !WIN32 */

#endif /* ANALYSISD_CORRELATION_SHARD_H */
