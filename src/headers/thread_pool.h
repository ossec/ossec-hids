/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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

typedef void (*thread_pool_drop_fn)(void *arg);

typedef struct thread_pool {
    int max_workers;
    int max_tasks;
    int workers_started;
    int active_workers;
    int pending;
    /* Idle workers that claimed a drop for a queued task; decremented when
     * that waiter is dequeued. Caps concurrent idle closes to pending. */
    int idle_drop_claims;
    int shutdown;
    thread_pool_drop_fn drop_fn;
    pthread_mutex_t mu;
    pthread_cond_t work_cond;
    pthread_cond_t idle_cond;
    thread_pool_task *head;
    thread_pool_task *tail;
    pthread_t *workers;
} thread_pool;

#ifdef THREAD_POOL_TEST_HOOK
extern int thread_pool_test_fail_worker_at;
#endif

thread_pool *thread_pool_create(int max_workers);
thread_pool *thread_pool_create_limited(int max_workers, int max_tasks);

/* Shutdown-only: joins workers, then frees any queued tasks without running
 * handlers. drop_fn (if set) is called on each dropped task arg. */
void thread_pool_destroy(thread_pool *pool);

void thread_pool_set_drop_fn(thread_pool *pool, thread_pool_drop_fn fn);

/* Returns 0 on success, -1 if at capacity, shutting down, or on error */
int thread_pool_submit(thread_pool *pool, thread_pool_fn fn, void *arg);

/* Bounded enqueue; same as thread_pool_submit (check and enqueue under one lock) */
int thread_pool_try_submit(thread_pool *pool, thread_pool_fn fn, void *arg);

int thread_pool_active(thread_pool *pool);

/* Returns 1 if an idle worker should close to free a slot for a queued task.
 * At most one claim per current waiter; each dequeue retires one claim so
 * remaining waiters can still free a quiet connection. */
int thread_pool_should_drop_idle(thread_pool *pool);

/* Wait until no pending or active tasks. Returns 0 when idle, 1 on timeout, -1 on error. */
int thread_pool_wait_idle(thread_pool *pool, int timeout_sec);

#endif /* !WIN32 */

#endif /* THREAD_POOL_H */
