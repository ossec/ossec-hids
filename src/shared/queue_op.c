/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "shared.h"
#include "queue_op.h"

os_queue *os_queue_init(size_t size)
{
    os_queue *queue;

    if (size < 2) {
        return NULL;
    }

    os_calloc(1, sizeof(os_queue), queue);
    os_malloc(size * sizeof(void *), queue->data);
    queue->size = size;
    queue->elements = 0;
    queue->shutdown = 0;
    os_mutex_init(&queue->mutex, NULL);
    os_cond_init(&queue->available, NULL);
    os_cond_init(&queue->available_not_empty, NULL);
    return queue;
}

void os_queue_destroy(os_queue *queue)
{
    if (!queue) {
        return;
    }

    free(queue->data);
    os_mutex_destroy(&queue->mutex);
    os_cond_destroy(&queue->available);
    os_cond_destroy(&queue->available_not_empty);
    free(queue);
}

void os_queue_shutdown(os_queue *queue)
{
    if (!queue) {
        return;
    }

    os_mutex_lock(&queue->mutex);
    queue->shutdown = 1;
    os_cond_broadcast(&queue->available);
    os_cond_broadcast(&queue->available_not_empty);
    os_mutex_unlock(&queue->mutex);
}

/* Unlocked helpers — callers must hold queue->mutex. */
static int os_queue_full(const os_queue *queue)
{
    return (queue->begin + 1) % queue->size == queue->end;
}

static int os_queue_empty(const os_queue *queue)
{
    return queue->begin == queue->end;
}

unsigned int os_queue_elements(os_queue *queue)
{
    unsigned int elements;

    if (!queue) {
        return 0;
    }

    /* Public reader used by metrics/FTS flush — must not race push/pop. */
    os_mutex_lock(&queue->mutex);
    elements = queue->elements;
    os_mutex_unlock(&queue->mutex);
    return elements;
}

static int os_queue_push(os_queue *queue, void *data)
{
    if (os_queue_full(queue)) {
        return -1;
    }

    queue->data[queue->begin] = data;
    queue->begin = (queue->begin + 1) % queue->size;
    queue->elements++;
    return 0;
}

static void *os_queue_pop(os_queue *queue)
{
    void *data;

    if (os_queue_empty(queue)) {
        return NULL;
    }

    data = queue->data[queue->end];
    queue->end = (queue->end + 1) % queue->size;
    queue->elements--;
    return data;
}

int os_queue_push_ex(os_queue *queue, void *data)
{
    int result;

    if (!queue || !data) {
        return -1;
    }

    os_mutex_lock(&queue->mutex);

    if (queue->shutdown) {
        os_mutex_unlock(&queue->mutex);
        return -1;
    }

    result = os_queue_push(queue, data);
    if (result == 0) {
        os_cond_signal(&queue->available);
    }

    os_mutex_unlock(&queue->mutex);
    return result;
}

int os_queue_push_ex_block(os_queue *queue, void *data)
{
    int result;

    if (!queue || !data) {
        return -1;
    }

    os_mutex_lock(&queue->mutex);

    while (!queue->shutdown && os_queue_full(queue)) {
        os_cond_wait(&queue->available_not_empty, &queue->mutex);
    }

    if (queue->shutdown) {
        os_mutex_unlock(&queue->mutex);
        return -1;
    }

    result = os_queue_push(queue, data);
    if (result == 0) {
        /* Wake a consumer waiting for data — not producers waiting for space. */
        os_cond_signal(&queue->available);
    }
    os_mutex_unlock(&queue->mutex);

    return result;
}

int os_queue_push_ex_timedwait(os_queue *queue, void *data, const struct timespec *abstime)
{
    int result;

    if (!queue || !abstime || !data) {
        return -1;
    }

    os_mutex_lock(&queue->mutex);

    while (!queue->shutdown && os_queue_full(queue)) {
        if (pthread_cond_timedwait(&queue->available_not_empty, &queue->mutex,
                                   abstime) != 0) {
            os_mutex_unlock(&queue->mutex);
            return -1;
        }
    }

    if (queue->shutdown) {
        os_mutex_unlock(&queue->mutex);
        return -1;
    }

    result = os_queue_push(queue, data);
    if (result == 0) {
        os_cond_signal(&queue->available);
    }
    os_mutex_unlock(&queue->mutex);

    return result;
}

void *os_queue_pop_ex(os_queue *queue)
{
    void *data;

    os_mutex_lock(&queue->mutex);

    while ((data = os_queue_pop(queue)) == NULL && !queue->shutdown) {
        os_cond_wait(&queue->available, &queue->mutex);
    }

    if (data) {
        os_cond_signal(&queue->available_not_empty);
    }

    os_mutex_unlock(&queue->mutex);
    return data;
}

void *os_queue_pop_ex_timedwait(os_queue *queue, const struct timespec *abstime)
{
    void *data;

    os_mutex_lock(&queue->mutex);

    while ((data = os_queue_pop(queue)) == NULL && !queue->shutdown) {
        if (pthread_cond_timedwait(&queue->available, &queue->mutex, abstime) != 0) {
            os_mutex_unlock(&queue->mutex);
            return NULL;
        }
    }

    if (data) {
        os_cond_signal(&queue->available_not_empty);
    }

    os_mutex_unlock(&queue->mutex);
    return data;
}

void os_queue_free_data(os_queue *queue, void (*freefn)(void *))
{
    void *data;

    if (!queue) {
        return;
    }

    os_mutex_lock(&queue->mutex);
    while ((data = os_queue_pop(queue)) != NULL) {
        if (freefn) {
            freefn(data);
        }
    }
    os_mutex_unlock(&queue->mutex);
}

#endif /* !WIN32 */
