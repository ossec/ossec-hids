/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SMS_QUEUE_H
#define SMS_QUEUE_H

#include "maild.h"

void OS_SmsQueueInit(void);
void OS_SmsEnqueue(MailMsg *msg) __attribute__((nonnull));
MailMsg *OS_SmsDequeue(void);
void OS_SmsRequeueFront(MailMsg *msg) __attribute__((nonnull));
int OS_SmsQueuePending(void);
void OS_SmsQueueClear(void);

#endif /* SMS_QUEUE_H */
