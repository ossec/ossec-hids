/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#ifndef WIN32

#include <pthread.h>

typedef void *(*thread_pool_fn)(void *arg);

typedef struct thread_pool_task {
    thread_pool_fn fn;
    void *arg;
    struct thread_pool_task *next;
} thread_pool_task;

typedef struct thread_pool {
    int max_workers;
    int max_tasks;
    int active_workers;
    int pending;
    int shutdown;
    pthread_mutex_t mu;
    pthread_cond_t work_cond;
    thread_pool_task *head;
    thread_pool_task *tail;
    pthread_t *workers;
} thread_pool;

thread_pool *thread_pool_create(int max_workers);
thread_pool *thread_pool_create_limited(int max_workers, int max_tasks);
void thread_pool_destroy(thread_pool *pool);

/* Returns 0 on success, -1 if at capacity or on error */
int thread_pool_submit(thread_pool *pool, thread_pool_fn fn, void *arg);

/* Atomic check-and-submit; prefer over has_slot + submit */
int thread_pool_try_submit(thread_pool *pool, thread_pool_fn fn, void *arg);

int thread_pool_active(thread_pool *pool);
int thread_pool_has_slot(thread_pool *pool);

#endif /* !WIN32 */

#endif /* THREAD_POOL_H */
