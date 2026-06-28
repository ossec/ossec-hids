/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _MAILLIST__H
#define _MAILLIST__H

/* Events List structure */
typedef struct _MailNode {
    MailMsg *mail;
    struct _MailNode *next;
    struct _MailNode *prev;
} MailNode;

/* Add an email to the list */
void OS_AddMailtoList(MailMsg *ml) __attribute__((nonnull));

/* Return the last event from the Event list
 * removing it from there
 */
MailNode *OS_PopLastMail(void);

/* Detach all queued mail into a list (oldest first via ->next). Caller frees nodes. */
MailNode *OS_DrainMailList(void);

/* mail_list_mu must already be held (lock order: mail_send_mu then mail_list_mu).
 * Do not call OS_CheckLastMail() while holding mail_workers_mu (nested lock). */
MailNode *OS_DrainMailListUnlocked(void);

/* Re-insert a detached batch (oldest first via ->next). mail_list_mu must be held. */
void OS_RequeueMailBatch(MailNode *batch);

void OS_MailListLock(void);
void OS_MailListUnlock(void);

/* Return a pointer to the last email, not removing it */
MailNode *OS_CheckLastMail(void);

/* Number of messages currently queued in the mail list. */
int OS_MailListPending(void);

/* Create the mail list. Maxsize must be specified */
void OS_CreateMailList(int maxsize);

/* Free an email node */
void FreeMail(MailNode *ml);

/* Free email msg */
void FreeMailMsg(MailMsg *ml);

#endif /* _MAILLIST__H */

