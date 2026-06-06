/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "maild.h"
#include "mail_list.h"
#include "error_messages/error_messages.h"

static MailNode *n_node;
static MailNode *lastnode;

static int _memoryused = 0;
static int _memorymaxsize = 0;
static pthread_mutex_t mail_list_mu;
static int mail_list_mu_ready = 0;


/* Create the Mail List */
void OS_CreateMailList(int maxsize)
{
    if (!mail_list_mu_ready) {
        os_mutex_init(&mail_list_mu, NULL);
        mail_list_mu_ready = 1;
    }

    os_mutex_lock(&mail_list_mu);
    n_node = NULL;
    lastnode = NULL;
    _memorymaxsize = maxsize;
    _memoryused = 0;
    os_mutex_unlock(&mail_list_mu);

    return;
}

/* Check last mail */
MailNode *OS_CheckLastMail()
{
    MailNode *node;

    os_mutex_lock(&mail_list_mu);
    node = lastnode;
    os_mutex_unlock(&mail_list_mu);

    return (node);
}

/* Get the last Mail -- or first node */
MailNode *OS_PopLastMail()
{
    MailNode *oldlast;

    os_mutex_lock(&mail_list_mu);
    oldlast = lastnode;
    if (lastnode == NULL) {
        n_node = NULL;
        os_mutex_unlock(&mail_list_mu);
        return (NULL);
    }

    _memoryused--;
    lastnode = lastnode->prev;
    os_mutex_unlock(&mail_list_mu);

    /* Remove the last */
    return (oldlast);
}

static MailNode *drain_list_oldest_first(void)
{
    MailNode *head = NULL;
    MailNode *tail = NULL;

    while (lastnode) {
        MailNode *n = lastnode;

        lastnode = n->prev;
        _memoryused--;
        n->prev = NULL;
        n->next = NULL;
        if (!head) {
            head = tail = n;
        } else {
            tail->next = n;
            tail = n;
        }
    }
    n_node = NULL;

    return (head);
}

void OS_MailListLock(void)
{
    os_mutex_lock(&mail_list_mu);
}

void OS_MailListUnlock(void)
{
    os_mutex_unlock(&mail_list_mu);
}

/* Drain entire list; oldest node first, newer nodes via ->next */
MailNode *OS_DrainMailList(void)
{
    MailNode *head;

    os_mutex_lock(&mail_list_mu);
    head = drain_list_oldest_first();
    os_mutex_unlock(&mail_list_mu);

    return (head);
}

MailNode *OS_DrainMailListUnlocked(void)
{
    return drain_list_oldest_first();
}

void OS_RequeueMailBatch(MailNode *batch)
{
    MailNode *n;
    MailNode *cur;
    MailNode *older;
    MailNode *newest;
    MailNode *prev_next;
    int count = 0;

    if (!batch) {
        return;
    }

    /* Detached batch is oldest-first via ->next; live queue is newest-first. */
    prev_next = NULL;
    cur = batch;
    while (cur) {
        older = cur->next;
        cur->next = prev_next;
        prev_next = cur;
        cur = older;
        count++;
    }
    newest = prev_next;

    if (n_node) {
        newest->next = n_node;
        n_node->prev = newest;
        n_node = newest;
    } else {
        n_node = newest;
    }

    lastnode = newest;
    while (lastnode->next) {
        lastnode = lastnode->next;
    }

    n_node->prev = NULL;
    for (n = n_node; n->next; n = n->next) {
        n->next->prev = n;
    }

    _memoryused += count;

    while (_memoryused > _memorymaxsize && lastnode) {
        MailNode *oldlast = lastnode;

        lastnode = lastnode->prev;
        if (n_node == oldlast) {
            n_node = oldlast->next;
            if (n_node) {
                n_node->prev = NULL;
            }
        } else if (oldlast->next) {
            oldlast->next->prev = lastnode;
        }
        FreeMail(oldlast);
        _memoryused--;
    }
}

void FreeMailMsg(MailMsg *ml)
{
    if (ml == NULL) {
        return;
    }

    if (ml->subject) {
        free(ml->subject);
    }

    if (ml->body) {
        free(ml->body);
    }

    free(ml);
}

/* Free mail node */
void FreeMail(MailNode *ml)
{
    if (ml == NULL) {
        return;
    }
    if (ml->mail->subject) {
        free(ml->mail->subject);
    }

    if (ml->mail->body) {
        free(ml->mail->body);
    }

    free(ml->mail);
    free(ml);
}


/* Add an email to the list -- always to the beginning */
void OS_AddMailtoList(MailMsg *ml)
{
    MailNode *tmp_node;

    os_mutex_lock(&mail_list_mu);
    tmp_node = n_node;

    if (tmp_node) {
        MailNode *new_node;
        new_node = (MailNode *)calloc(1, sizeof(MailNode));

        if (new_node == NULL) {
            os_mutex_unlock(&mail_list_mu);
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        /* Always add to the beginning of the list
         * The new node will become the first node and
         * new_node->next will be the previous first node
         */
        new_node->next = tmp_node;
        new_node->prev = NULL;
        tmp_node->prev = new_node;

        n_node = new_node;

        /* Add the event to the node */
        new_node->mail = ml;

        _memoryused++;

        /* Need to remove the last node */
        if (_memoryused > _memorymaxsize) {
            MailNode *oldlast;

            oldlast = lastnode;
            lastnode = lastnode->prev;

            /* Free last node */
            FreeMail(oldlast);

            _memoryused--;
        }
    }

    else {
        /* Add first node */
        n_node = (MailNode *)calloc(1, sizeof(MailNode));
        if (n_node == NULL) {
            os_mutex_unlock(&mail_list_mu);
            ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        n_node->prev = NULL;
        n_node->next = NULL;
        n_node->mail = ml;

        lastnode = n_node;
    }

    os_mutex_unlock(&mail_list_mu);

    return;
}
