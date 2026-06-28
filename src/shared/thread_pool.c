/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include <errno.h>
#include <time.h>

#include "shared.h"
#include "thread_pool.h"

#ifdef THREAD_POOL_TEST_HOOK
int thread_pool_test_fail_worker_at = -1;
#endif

static void *thread_pool_worker(void *arg)
{
    thread_pool *pool = (thread_pool *)arg;
    thread_pool_task *task;

    os_block_worker_signals();

    while (1) {
        os_mutex_lock(&pool->mu);

        while (!pool->shutdown && pool->head == NULL) {
            os_cond_wait(&pool->work_cond, &pool->mu);
        }

        /* On shutdown, stop dequeuing; in-flight tasks still run to completion. */
        if (pool->shutdown) {
            os_mutex_unlock(&pool->mu);
            break;
        }

        task = pool->head;
        pool->head = task->next;
        if (pool->head == NULL) {
            pool->tail = NULL;
        }
        pool->pending--;
        pool->active_workers++;

        os_mutex_unlock(&pool->mu);

        task->fn(task->arg);
        free(task);

        os_mutex_lock(&pool->mu);
        pool->active_workers--;
        if (pool->active_workers == 0 && pool->pending == 0) {
            os_cond_broadcast(&pool->idle_cond);
        }
        os_mutex_unlock(&pool->mu);
    }

    return NULL;
}

static void thread_pool_flush_pending(thread_pool *pool)
{
    thread_pool_task *task;

    os_mutex_lock(&pool->mu);

    while (pool->head) {
        task = pool->head;
        pool->head = task->next;
        pool->pending--;
        os_mutex_unlock(&pool->mu);

        if (pool->drop_fn && task->arg) {
            pool->drop_fn(task->arg);
        }
        free(task);

        os_mutex_lock(&pool->mu);
    }

    pool->tail = NULL;
    os_mutex_unlock(&pool->mu);
}

thread_pool *thread_pool_create_limited(int max_workers, int max_tasks)
{
    thread_pool *pool;
    int i;

    if (max_workers < 1) {
        return NULL;
    }

    os_calloc(1, sizeof(thread_pool), pool);
    pool->max_workers = max_workers;
    pool->max_tasks = max_tasks;
    pool->workers_started = 0;
    os_calloc((size_t)max_workers, sizeof(pthread_t), pool->workers);

    os_mutex_init(&pool->mu, NULL);
    os_cond_init(&pool->work_cond, NULL);
    os_cond_init(&pool->idle_cond, NULL);

    for (i = 0; i < max_workers; i++) {
#ifdef THREAD_POOL_TEST_HOOK
        if (thread_pool_test_fail_worker_at == i) {
            os_mutex_lock(&pool->mu);
            pool->shutdown = 1;
            os_cond_broadcast(&pool->work_cond);
            os_mutex_unlock(&pool->mu);
            thread_pool_destroy(pool);
            return NULL;
        }
#endif
        if (CreateThreadJoinable(&pool->workers[i], thread_pool_worker, pool) != 0) {
            os_mutex_lock(&pool->mu);
            pool->shutdown = 1;
            os_cond_broadcast(&pool->work_cond);
            os_mutex_unlock(&pool->mu);
            thread_pool_destroy(pool);
            return NULL;
        }
        pool->workers_started++;
    }

    return pool;
}

thread_pool *thread_pool_create(int max_workers)
{
    return thread_pool_create_limited(max_workers, 0);
}

void thread_pool_destroy(thread_pool *pool)
{
    int i;

    if (!pool) {
        return;
    }

    os_mutex_lock(&pool->mu);
    pool->shutdown = 1;
    os_cond_broadcast(&pool->work_cond);
    os_mutex_unlock(&pool->mu);

    for (i = 0; i < pool->workers_started; i++) {
        pthread_join(pool->workers[i], NULL);
    }

    thread_pool_flush_pending(pool);

    os_mutex_destroy(&pool->mu);
    os_cond_destroy(&pool->work_cond);
    os_cond_destroy(&pool->idle_cond);
    free(pool->workers);
    free(pool);
}

void thread_pool_set_drop_fn(thread_pool *pool, thread_pool_drop_fn fn)
{
    if (!pool) {
        return;
    }

    os_mutex_lock(&pool->mu);
    pool->drop_fn = fn;
    os_mutex_unlock(&pool->mu);
}

int thread_pool_active(thread_pool *pool)
{
    int total;

    if (!pool) {
        return 0;
    }

    os_mutex_lock(&pool->mu);
    total = pool->active_workers + pool->pending;
    os_mutex_unlock(&pool->mu);

    return total;
}

int thread_pool_submit(thread_pool *pool, thread_pool_fn fn, void *arg)
{
    thread_pool_task *task;

    if (!pool || !fn) {
        return -1;
    }

    os_mutex_lock(&pool->mu);

    if (pool->shutdown) {
        os_mutex_unlock(&pool->mu);
        return -1;
    }

    if (pool->max_tasks > 0 &&
        pool->active_workers + pool->pending >= pool->max_tasks) {
        os_mutex_unlock(&pool->mu);
        return -1;
    }

    task = (thread_pool_task *)calloc(1, sizeof(thread_pool_task));
    if (!task) {
        os_mutex_unlock(&pool->mu);
        return -1;
    }
    task->fn = fn;
    task->arg = arg;

    if (pool->tail) {
        pool->tail->next = task;
    } else {
        pool->head = task;
    }
    pool->tail = task;
    pool->pending++;

    os_cond_signal(&pool->work_cond);
    os_mutex_unlock(&pool->mu);

    return 0;
}

int thread_pool_try_submit(thread_pool *pool, thread_pool_fn fn, void *arg)
{
    /* Bounded enqueue under one lock; identical to thread_pool_submit. */
    return thread_pool_submit(pool, fn, arg);
}

int thread_pool_wait_idle(thread_pool *pool, int timeout_sec)
{
    struct timespec deadline;
    struct timespec now;
    int ret = 0;

    if (!pool || timeout_sec < 0) {
        return -1;
    }

    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return -1;
    }

    deadline.tv_sec = now.tv_sec + timeout_sec;
    deadline.tv_nsec = now.tv_nsec;

    os_mutex_lock(&pool->mu);

    while (pool->active_workers > 0 || pool->pending > 0) {
        ret = pthread_cond_timedwait(&pool->idle_cond, &pool->mu, &deadline);
        if (ret == ETIMEDOUT) {
            os_mutex_unlock(&pool->mu);
            return 1;
        }
        if (ret != 0) {
            os_mutex_unlock(&pool->mu);
            return -1;
        }
    }

    os_mutex_unlock(&pool->mu);
    return 0;
}

#endif /* !WIN32 */
