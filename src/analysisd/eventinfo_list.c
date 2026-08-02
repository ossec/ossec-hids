/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "eventinfo.h"
#include "rules.h"
#include "correlation_shard.h"

/* Global default list (legacy / single-thread). Match workers may install a
 * private shard list via analysisd_set_event_list(). */
static EventList g_event_list;
static __thread EventList *tls_event_list = NULL;

int _max_freq = 0;

EventList *analysisd_get_event_list(void)
{
    return tls_event_list ? tls_event_list : &g_event_list;
}

void analysisd_set_event_list(EventList *list)
{
    tls_event_list = list;
}

static void os_eventlist_init(EventList *list, int maxsize)
{
    list->first = NULL;
    list->last = NULL;
    list->memoryused = 0;
    list->memorymaxsize = maxsize;
    os_mutex_init(&list->mutex, NULL);
}

/* Create the Event List */
void OS_CreateEventList(int maxsize)
{
    os_eventlist_init(&g_event_list, maxsize);
    tls_event_list = NULL;
    debug1("%s: OS_CreateEventList completed.", ARGV0);
}

EventList *OS_EventList_Create(int maxsize)
{
    EventList *list;

    os_calloc(1, sizeof(EventList), list);
    os_eventlist_init(list, maxsize);
    return list;
}

void OS_EventList_Destroy(EventList *list)
{
    EventNode *node;
    EventNode *next;

    if (!list) {
        return;
    }

    /* Unlink under the list lock; Free_Eventinfo after unlock so we never
     * nest rule->mutex under list->mutex (Search_LastEvents takes the
     * opposite order). */
    os_mutex_lock(&list->mutex);
    node = list->first;
    list->first = NULL;
    list->last = NULL;
    list->memoryused = 0;
    os_mutex_unlock(&list->mutex);

    while (node) {
        next = node->next;
        if (node->event) {
            Free_Eventinfo(node->event);
        }
        free(node);
        node = next;
    }
    os_mutex_destroy(&list->mutex);
    free(list);
}

/* Get the last event -- or first node */
EventNode *OS_GetLastEvent_List(EventList *list)
{
    if (!list) {
        return NULL;
    }
    return list->first;
}

EventNode *OS_GetLastEvent(void)
{
    return OS_GetLastEvent_List(analysisd_get_event_list());
}

void OS_AddEvent_List(Eventinfo *lf, EventList *list)
{
    EventNode *tmp_node;
    EventNode *victims = NULL;

    if (!list || !lf) {
        return;
    }

    os_mutex_lock(&list->mutex);
    tmp_node = list->first;

    if (tmp_node) {
        EventNode *new_node;
        new_node = (EventNode *)calloc(1, sizeof(EventNode));

        if (new_node == NULL) {
            os_mutex_unlock(&list->mutex);
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        new_node->next = tmp_node;
        new_node->prev = NULL;
        tmp_node->prev = new_node;

        list->first = new_node;
        new_node->event = lf;

        list->memoryused++;

        if (list->memoryused > list->memorymaxsize) {
            int i = 0;
            EventNode *oldlast;

            while (list->last &&
                   ((i < 10) || ((lf->time - list->last->event->time) > _max_freq))) {
                oldlast = list->last;
                list->last = list->last->prev;
                if (list->last) {
                    list->last->next = NULL;
                } else {
                    list->first = NULL;
                }

                /* Defer Free_Eventinfo: it may lock generated_rule->mutex. */
                oldlast->prev = NULL;
                oldlast->next = victims;
                victims = oldlast;

                list->memoryused--;
                i++;
                if (!list->last) {
                    break;
                }
            }
        }
    } else {
        list->first = (EventNode *)calloc(1, sizeof(EventNode));
        if (list->first == NULL) {
            os_mutex_unlock(&list->mutex);
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        list->first->prev = NULL;
        list->first->next = NULL;
        list->first->event = lf;
        list->last = list->first;
        list->memoryused = 1;
    }

    os_mutex_unlock(&list->mutex);

    while (victims) {
        EventNode *node = victims;
        victims = victims->next;
        if (node->event) {
            Free_Eventinfo(node->event);
        }
        free(node);
    }
}

void OS_AddEvent(Eventinfo *lf)
{
    OS_AddEvent_List(lf, analysisd_get_event_list());
}
