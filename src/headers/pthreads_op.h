/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef PTHREADS_OP_H
#define PTHREADS_OP_H

#ifndef WIN32

#include <pthread.h>

#define OS_THREAD_STACK_DEFAULT_KB 2048

size_t os_thread_stack_size(void);

void os_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
void os_mutex_lock(pthread_mutex_t *mutex);
void os_mutex_unlock(pthread_mutex_t *mutex);
void os_mutex_destroy(pthread_mutex_t *mutex);

void os_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
void os_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
void os_cond_signal(pthread_cond_t *cond);
void os_cond_broadcast(pthread_cond_t *cond);
void os_cond_destroy(pthread_cond_t *cond);

/* Returns 0 on success, -1 on error */
int CreateThread(void *function_pointer(void *data), void *data) __attribute__((nonnull(1)));

/* Returns 0 on success, -1 on error; thread must be joined or detached by caller */
int CreateThreadJoinable(pthread_t *tid, void *(*function_pointer)(void *), void *arg)
    __attribute__((nonnull(1, 2)));

/* Block process-exit signals in pool/worker threads (main keeps handlers) */
void os_block_worker_signals(void);

#endif /* !WIN32 */

#endif /* PTHREADS_OP_H */
