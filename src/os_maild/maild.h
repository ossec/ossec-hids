/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MAILD_H
#define _MAILD_H

#define MAIL_LIST_SIZE      96   /* Max number of emails to be saved */
#define MAX_MAIL_WORKERS    6    /* Maximum simultaneous mail send threads */
#define MAXCHILDPROCESS     MAX_MAIL_WORKERS
#define MAX_SEND_ERRORS     6    /* SMTP failures before backoff (issue #1890) */
#define SMTP_BACKOFF_SEC    30   /* Pause after too many SMTP failures */

/* Each timeout is x * 5 */
#define NEXTMAIL_TIMEOUT    2    /* Time to check for next msg - 5 */
#define DEFAULT_TIMEOUT     18   /* socket read timeout - 18 (*5)*/
#define SUBJECT_SIZE        128  /* Maximum subject size */

/* Maximum body size */
#define BODY_SIZE           OS_MAXSTR + OS_SIZE_1024

#define SMS_SUBJECT         "OSSEC %d - %d - %s"
#define MAIL_SUBJECT        "OSSEC Notification - %s - Alert level %d"
#define MAIL_SUBJECT_FULL   "OSSEC Alert - %s - Level %d - %s"

/* Full subject without ossec in the name */
#ifdef CLEANFULL
#define MAIL_SUBJECT_FULL2   "%d - %s - %s"
#endif

#ifdef LIBGEOIP_ENABLED
#define MAIL_BODY           "\r\nOSSEC HIDS Notification.\r\n" \
                            "%s\r\n\r\n" \
                            "Received From: %s\r\n" \
                            "Rule: %d fired (level %d) -> \"%s\"\r\n" \
                            "%s" \
                            "%s" \
                            "%s" \
                            "Portion of the log(s):\r\n\r\n%s\r\n" \
                            "\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n"
#else
#define MAIL_BODY           "\r\nOSSEC HIDS Notification.\r\n" \
                            "%s\r\n\r\n" \
                            "Received From: %s\r\n" \
                            "Rule: %d fired (level %d) -> \"%s\"\r\n" \
                            "%s" \
                            "Portion of the log(s):\r\n\r\n%s\r\n" \
                            "\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n"
#endif

/* Mail msg structure */
typedef struct _MailMsg {
    char *subject;
    char *body;
} MailMsg;

typedef struct _MailNode MailNode;

#include "shared.h"
#include "config/mail-config.h"

/* Config function */
int MailConf(int test_config, const char *cfgfile, MailConfig *Mail) __attribute__((nonnull));

/* Receive the e-mail message (SMS alerts are enqueued via OS_SmsEnqueue). */
MailMsg *OS_RecvMailQ(file_queue *fileq, struct tm *p, MailConfig *mail)
    __attribute__((nonnull));

/* Send SMS to granular recipients marked SMS_FORMAT (gran_override may be NULL). */
int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *sms_msg,
               const int *gran_set_override) __attribute__((nonnull(1, 2, 3)));

/* Send an email from a detached batch (oldest first via MailNode->next).
 * gran_set_override may be NULL to use mail->gran_set.
 * group_subject/group_subject_level: snapshotted grouped subject (level 0 or empty = per-message).
 * Frees all batch nodes. */
int OS_Sendmail(MailConfig *mail, struct tm *p, MailNode *batch,
                const int *gran_set_override, const char *group_subject,
                unsigned int group_subject_level) __attribute__((nonnull(1, 2, 3)));

/* MailConfig is read by worker threads after startup; treat as immutable unless
 * hot-reload is added (then snapshot smtp server and auth into worker args). */

/* Held while updating live gran_set / _g_subject and during send */
extern pthread_mutex_t mail_send_mu;
int OS_SendCustomEmail(char **to, char *subject, char *smtpserver, char *from, char *idsname, char *fname, const struct tm *p);

/* Mail timeout used by the file-queue */
extern unsigned int mail_timeout;

/* Global var for highest level on mail subjects */
extern unsigned int   _g_subject_level;
extern char _g_subject[SUBJECT_SIZE + 2];

#endif

