/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Thread pool smoke test - build: make -C shared/tests thread_pool_test */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "shared.h"

int getDefine_Int(const char *section, const char *key, int min, int max)
{
    (void)section;
    (void)key;
    (void)max;
    return min;
}

static int completed = 0;
static int dropped = 0;
static pthread_mutex_t done_mu = PTHREAD_MUTEX_INITIALIZER;

static void *count_task(void *arg)
{
    int id = *(int *)arg;
    free(arg);
    usleep(10000);
    os_mutex_lock(&done_mu);
    completed++;
    os_mutex_unlock(&done_mu);
    (void)id;
    return NULL;
}

static void *block_task(void *arg)
{
    (void)arg;
    usleep(200000);
    return NULL;
}

static void track_drop(void *arg)
{
    free(arg);
    os_mutex_lock(&done_mu);
    dropped++;
    os_mutex_unlock(&done_mu);
}

int main(void)
{
    thread_pool *pool;
    int i;

    pool = thread_pool_create(4);
    if (!pool) {
        fprintf(stderr, "FAIL: thread_pool_create\n");
        return 1;
    }

    for (i = 0; i < 8; i++) {
        int *id = calloc(1, sizeof(int));
        *id = i;
        if (thread_pool_submit(pool, count_task, id) != 0) {
            fprintf(stderr, "FAIL: submit %d\n", i);
            thread_pool_destroy(pool);
            return 1;
        }
    }

    while (completed < 8) {
        usleep(50000);
    }

    thread_pool_destroy(pool);

    /* max_tasks = queued + active: third submit should fail until a slot frees */
    pool = thread_pool_create_limited(2, 2);
    if (!pool) {
        fprintf(stderr, "FAIL: thread_pool_create_limited\n");
        return 1;
    }

    if (thread_pool_submit(pool, block_task, NULL) != 0 ||
        thread_pool_submit(pool, block_task, NULL) != 0) {
        fprintf(stderr, "FAIL: backpressure setup submit\n");
        thread_pool_destroy(pool);
        return 1;
    }

    if (thread_pool_submit(pool, block_task, NULL) == 0) {
        fprintf(stderr, "FAIL: expected backpressure on third submit\n");
        thread_pool_destroy(pool);
        return 1;
    }

    usleep(300000);

    if (thread_pool_submit(pool, block_task, NULL) != 0) {
        fprintf(stderr, "FAIL: submit after slot freed\n");
        thread_pool_destroy(pool);
        return 1;
    }

    thread_pool_destroy(pool);

    /* drop_fn cleans args left on the queue after workers join. */
    dropped = 0;
    pool = thread_pool_create(1);
    if (!pool) {
        fprintf(stderr, "FAIL: thread_pool_create for drop_fn\n");
        return 1;
    }
    thread_pool_set_drop_fn(pool, track_drop);
    thread_pool_destroy(pool);
    if (dropped != 0) {
        fprintf(stderr, "FAIL: drop_fn on empty destroy, got %d\n", dropped);
        return 1;
    }

#ifdef THREAD_POOL_TEST_HOOK
    /* Partial worker create: destroy must join only started workers. */
    thread_pool_test_fail_worker_at = 2;
    pool = thread_pool_create_limited(4, 0);
    thread_pool_test_fail_worker_at = -1;
    if (pool != NULL) {
        fprintf(stderr, "FAIL: expected partial create to fail\n");
        thread_pool_destroy(pool);
        return 1;
    }
#endif

    printf("PASS: thread_pool_test\n");
    return 0;
}
