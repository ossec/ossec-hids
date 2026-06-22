/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include <pthread.h>

void os_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    int error = pthread_mutex_init(mutex, attr);
    if (error != 0) {
        ErrorExit("%s: At pthread_mutex_init(): %s", __local_name, strerror(error));
    }
}

void os_mutex_lock(pthread_mutex_t *mutex)
{
    int error = pthread_mutex_lock(mutex);
    if (error != 0) {
        ErrorExit("%s: At pthread_mutex_lock(): %s", __local_name, strerror(error));
    }
}

void os_mutex_unlock(pthread_mutex_t *mutex)
{
    int error = pthread_mutex_unlock(mutex);
    if (error != 0) {
        ErrorExit("%s: At pthread_mutex_unlock(): %s", __local_name, strerror(error));
    }
}

void os_mutex_destroy(pthread_mutex_t *mutex)
{
    int error = pthread_mutex_destroy(mutex);
    if (error != 0) {
        ErrorExit("%s: At pthread_mutex_destroy(): %s", __local_name, strerror(error));
    }
}

#ifndef WIN32

#include <signal.h>

size_t os_thread_stack_size(void)
{
    int stack_kb = getDefine_Int("ossec", "thread_stack_size",
                                 2048, 65536);

    return (size_t)stack_kb * 1024;
}

void os_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    int error = pthread_cond_init(cond, attr);
    if (error != 0) {
        ErrorExit("%s: At pthread_cond_init(): %s", __local_name, strerror(error));
    }
}

void os_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    int error = pthread_cond_wait(cond, mutex);
    if (error != 0) {
        ErrorExit("%s: At pthread_cond_wait(): %s", __local_name, strerror(error));
    }
}

void os_cond_signal(pthread_cond_t *cond)
{
    int error = pthread_cond_signal(cond);
    if (error != 0) {
        ErrorExit("%s: At pthread_cond_signal(): %s", __local_name, strerror(error));
    }
}

void os_cond_broadcast(pthread_cond_t *cond)
{
    int error = pthread_cond_broadcast(cond);
    if (error != 0) {
        ErrorExit("%s: At pthread_cond_broadcast(): %s", __local_name, strerror(error));
    }
}

void os_cond_destroy(pthread_cond_t *cond)
{
    int error = pthread_cond_destroy(cond);
    if (error != 0) {
        ErrorExit("%s: At pthread_cond_destroy(): %s", __local_name, strerror(error));
    }
}

void os_block_worker_signals(void)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGALRM);

    {
        int ret = pthread_sigmask(SIG_BLOCK, &set, NULL);

        if (ret != 0) {
            merror("%s: pthread_sigmask failed: %s", __local_name, strerror(ret));
        }
    }
}

int CreateThreadJoinable(pthread_t *tid, void *(*function_pointer)(void *), void *arg)
{
    pthread_attr_t attr;
    int ret;

    if (pthread_attr_init(&attr) != 0) {
        merror(THREAD_ERROR, __local_name);
        return -1;
    }

    if (pthread_attr_setstacksize(&attr, os_thread_stack_size()) != 0) {
        merror(THREAD_ERROR, __local_name);
        pthread_attr_destroy(&attr);
        return -1;
    }

    ret = pthread_create(tid, &attr, function_pointer, arg);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        merror(THREAD_ERROR, __local_name);
        return -1;
    }

    return 0;
}

int CreateThread(void *function_pointer(void *data), void *data)
{
    pthread_t lthread;

    if (CreateThreadJoinable(&lthread, function_pointer, data) != 0) {
        return -1;
    }

    if (pthread_detach(lthread) != 0) {
        merror(THREAD_ERROR, __local_name);
        return -1;
    }

    return 0;
}

#endif /* !WIN32 */
