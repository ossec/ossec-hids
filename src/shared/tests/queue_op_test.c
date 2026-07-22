/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "queue_op.h"

/* Symbols required by shared.a helpers. */
const char *__local_name = "queue_op_test";

int getDefine_Int(const char *section, const char *key, int min, int max)
{
    (void)section;
    (void)key;
    (void)max;
    return min;
}

static int test_basic_push_pop(void)
{
    os_queue *queue;
    int i;

    queue = os_queue_init(4);
    if (!queue) {
        fprintf(stderr, "FAIL: os_queue_init\n");
        return 1;
    }

    for (i = 0; i < 3; i++) {
        char *item = strdup("event");
        if (os_queue_push_ex(queue, item) != 0) {
            fprintf(stderr, "FAIL: os_queue_push_ex %d\n", i);
            free(item);
            os_queue_destroy(queue);
            return 1;
        }
    }

    if (os_queue_push_ex(queue, (void *)"overflow") == 0) {
        fprintf(stderr, "FAIL: expected full queue push to fail\n");
        os_queue_destroy(queue);
        return 1;
    }

    for (i = 0; i < 3; i++) {
        char *item = (char *)os_queue_pop_ex(queue);
        if (!item || strcmp(item, "event") != 0) {
            fprintf(stderr, "FAIL: os_queue_pop_ex %d\n", i);
            os_queue_destroy(queue);
            return 1;
        }
        free(item);
    }

    os_queue_shutdown(queue);
    os_queue_destroy(queue);
    return 0;
}

static int test_timedwait_timeout_on_full(void)
{
    os_queue *queue;
    struct timespec ts;
    char *item;
    int i;
    int rc;

    queue = os_queue_init(3);
    if (!queue) {
        fprintf(stderr, "FAIL: os_queue_init timedwait\n");
        return 1;
    }

    for (i = 0; i < 2; i++) {
        item = strdup("fill");
        if (os_queue_push_ex(queue, item) != 0) {
            fprintf(stderr, "FAIL: fill push %d\n", i);
            free(item);
            os_queue_destroy(queue);
            return 1;
        }
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fprintf(stderr, "FAIL: clock_gettime\n");
        os_queue_destroy(queue);
        return 1;
    }
    ts.tv_nsec += 50 * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    item = strdup("late");
    rc = os_queue_push_ex_timedwait(queue, item, &ts);
    if (rc == 0) {
        fprintf(stderr, "FAIL: expected timedwait push to fail on full queue\n");
        free(item);
        os_queue_destroy(queue);
        return 1;
    }
    free(item);

    os_queue_free_data(queue, free);
    os_queue_shutdown(queue);
    os_queue_destroy(queue);
    return 0;
}

static int test_block_push(void)
{
    os_queue *queue;
    char payload[16];

    queue = os_queue_init(4);
    if (!queue) {
        return 1;
    }

    snprintf(payload, sizeof(payload), "blocked");
    if (os_queue_push_ex_block(queue, payload) != 0) {
        fprintf(stderr, "FAIL: os_queue_push_ex_block\n");
        os_queue_destroy(queue);
        return 1;
    }

    if (os_queue_pop_ex(queue) != payload) {
        fprintf(stderr, "FAIL: pop after block push\n");
        os_queue_destroy(queue);
        return 1;
    }

    os_queue_shutdown(queue);
    os_queue_destroy(queue);
    return 0;
}

static int test_reject_null_push(void)
{
    os_queue *queue;
    struct timespec ts;

    queue = os_queue_init(4);
    if (!queue) {
        fprintf(stderr, "FAIL: os_queue_init null push\n");
        return 1;
    }

    if (os_queue_push_ex(queue, NULL) == 0) {
        fprintf(stderr, "FAIL: os_queue_push_ex accepted NULL\n");
        os_queue_destroy(queue);
        return 1;
    }
    if (os_queue_push_ex_block(queue, NULL) == 0) {
        fprintf(stderr, "FAIL: os_queue_push_ex_block accepted NULL\n");
        os_queue_destroy(queue);
        return 1;
    }
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fprintf(stderr, "FAIL: clock_gettime null push\n");
        os_queue_destroy(queue);
        return 1;
    }
    ts.tv_sec += 1;
    if (os_queue_push_ex_timedwait(queue, NULL, &ts) == 0) {
        fprintf(stderr, "FAIL: os_queue_push_ex_timedwait accepted NULL\n");
        os_queue_destroy(queue);
        return 1;
    }
    if (os_queue_elements(queue) != 0) {
        fprintf(stderr, "FAIL: null push mutated queue\n");
        os_queue_destroy(queue);
        return 1;
    }

    os_queue_shutdown(queue);
    os_queue_destroy(queue);
    return 0;
}

#define STRESS_PRODUCERS 4
#define STRESS_CONSUMERS 4
#define STRESS_PER_PRODUCER 2000

struct stress_ctx {
    os_queue *queue;
    unsigned int produced;
    unsigned int consumed;
    unsigned int sum_in;
    unsigned int sum_out;
};

static void *stress_producer(void *arg)
{
    struct stress_ctx *ctx = (struct stress_ctx *)arg;
    unsigned int i;

    for (i = 0; i < STRESS_PER_PRODUCER; i++) {
        unsigned int *payload = malloc(sizeof(unsigned int));

        if (!payload) {
            return (void *)(intptr_t)1;
        }
        *payload = i + 1;
        __sync_add_and_fetch(&ctx->sum_in, *payload);
        if (os_queue_push_ex_block(ctx->queue, payload) != 0) {
            free(payload);
            return (void *)(intptr_t)1;
        }
        __sync_add_and_fetch(&ctx->produced, 1);
    }

    return NULL;
}

static void *stress_consumer(void *arg)
{
    struct stress_ctx *ctx = (struct stress_ctx *)arg;

    while (1) {
        unsigned int *payload = (unsigned int *)os_queue_pop_ex(ctx->queue);

        if (!payload) {
            break;
        }
        __sync_add_and_fetch(&ctx->sum_out, *payload);
        __sync_add_and_fetch(&ctx->consumed, 1);
        free(payload);
    }

    return NULL;
}

/* Multi-producer / multi-consumer contention under lock. */
static int test_multithread_stress(void)
{
    struct stress_ctx ctx;
    pthread_t producers[STRESS_PRODUCERS];
    pthread_t consumers[STRESS_CONSUMERS];
    unsigned int expected;
    int i;
    void *ret;

    memset(&ctx, 0, sizeof(ctx));
    ctx.queue = os_queue_init(64);
    if (!ctx.queue) {
        fprintf(stderr, "FAIL: stress queue init\n");
        return 1;
    }

    for (i = 0; i < STRESS_CONSUMERS; i++) {
        if (pthread_create(&consumers[i], NULL, stress_consumer, &ctx) != 0) {
            fprintf(stderr, "FAIL: consumer create %d\n", i);
            return 1;
        }
    }
    for (i = 0; i < STRESS_PRODUCERS; i++) {
        if (pthread_create(&producers[i], NULL, stress_producer, &ctx) != 0) {
            fprintf(stderr, "FAIL: producer create %d\n", i);
            return 1;
        }
    }

    for (i = 0; i < STRESS_PRODUCERS; i++) {
        pthread_join(producers[i], &ret);
        if (ret != NULL) {
            fprintf(stderr, "FAIL: producer %d error\n", i);
            os_queue_shutdown(ctx.queue);
            for (i = 0; i < STRESS_CONSUMERS; i++) {
                pthread_join(consumers[i], NULL);
            }
            os_queue_destroy(ctx.queue);
            return 1;
        }
    }

    os_queue_shutdown(ctx.queue);

    for (i = 0; i < STRESS_CONSUMERS; i++) {
        pthread_join(consumers[i], NULL);
    }

    expected = STRESS_PRODUCERS * STRESS_PER_PRODUCER;
    if (ctx.produced != expected || ctx.consumed != expected) {
        fprintf(stderr, "FAIL: stress counts produced=%u consumed=%u expected=%u\n",
                ctx.produced, ctx.consumed, expected);
        os_queue_destroy(ctx.queue);
        return 1;
    }
    if (ctx.sum_in != ctx.sum_out) {
        fprintf(stderr, "FAIL: stress checksum in=%u out=%u\n",
                ctx.sum_in, ctx.sum_out);
        os_queue_destroy(ctx.queue);
        return 1;
    }

    os_queue_destroy(ctx.queue);
    printf("PASS: os_queue multithread stress (%u producers x %u items)\n",
           STRESS_PRODUCERS, STRESS_PER_PRODUCER);
    return 0;
}

int main(void)
{
    if (test_basic_push_pop() != 0) {
        return 1;
    }
    if (test_timedwait_timeout_on_full() != 0) {
        return 1;
    }
    if (test_block_push() != 0) {
        return 1;
    }
    if (test_reject_null_push() != 0) {
        return 1;
    }
    if (test_multithread_stress() != 0) {
        return 1;
    }

    printf("PASS: os_queue tests (push/pop, timedwait, block, null, stress)\n");
    return 0;
}

#endif
