/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef QUEUE_OP_H
#define QUEUE_OP_H

#ifndef WIN32

#include <pthread.h>
#include <time.h>

typedef struct os_queue {
    void **data;
    size_t begin;
    size_t end;
    size_t size;
    unsigned int elements;
    int shutdown;
    pthread_mutex_t mutex;
    pthread_cond_t available;
    pthread_cond_t available_not_empty;
} os_queue;

os_queue *os_queue_init(size_t size);
void os_queue_destroy(os_queue *queue);
void os_queue_shutdown(os_queue *queue);

/* Thread-safe API — always use these from outside queue_op.c.
 * Push APIs require data != NULL (NULL is reserved for empty pop / free_data end).
 */
int os_queue_push_ex(os_queue *queue, void *data);
int os_queue_push_ex_block(os_queue *queue, void *data);
/* Timed wait for space; returns -1 on timeout, shutdown, NULL data, or push failure. */
int os_queue_push_ex_timedwait(os_queue *queue, void *data, const struct timespec *abstime);

void *os_queue_pop_ex(os_queue *queue);
void *os_queue_pop_ex_timedwait(os_queue *queue, const struct timespec *abstime);

unsigned int os_queue_elements(os_queue *queue);

/* Pop and free every remaining element (caller supplies freefn). */
void os_queue_free_data(os_queue *queue, void (*freefn)(void *));

#endif /* !WIN32 */

#endif /* QUEUE_OP_H */
