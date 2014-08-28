/* @(#) $Id: ./src/os_maild/maild.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef _MAILD_H
#define _MAILD_H

#define MAIL_LIST_SIZE      96   /* Max number of emails to be saved */
#define MAXCHILDPROCESS     6    /* Maximum simultaneos childs */

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

#ifdef GEOIP
#define MAIL_BODY           "\r\nOSSEC HIDS Notification.\r\n" \
                            "%s\r\n\r\n" \
                            "Received From: %s\r\n" \
                            "Rule: %d fired (level %d) -> \"%s\"\r\n" \
			    "%s" \
                            "%s" \
                            "Portion of the log(s):\r\n\r\n%s\r\n" \
                            "\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n"
#else
#define MAIL_BODY           "\r\nOSSEC HIDS Notification.\r\n" \
                            "%s\r\n\r\n" \
                            "Received From: %s\r\n" \
                            "Rule: %d fired (level %d) -> \"%s\"\r\n" \
                            "Portion of the log(s):\r\n\r\n%s\r\n" \
                            "\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n"
#endif

/* Mail msg structure */
typedef struct _MailMsg
{
	char *subject;
	char *body;
}MailMsg;

#include "shared.h"
#include "config/mail-config.h"


/* Config function */
int MailConf(int test_config, char *cfgfile, MailConfig *Mail);


/* Receive the e-mail message */
MailMsg *OS_RecvMailQ(file_queue *fileq, struct tm *p, MailConfig *mail,
                      MailMsg **msg_sms);

/* Sends an email */
int OS_Sendmail(MailConfig *mail, struct tm *p);
int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *sms_msg);
int OS_SendCustomEmail(char **to, char *subject, char *smtpserver, char *from, char *idsname, FILE *fp, struct tm *p);


/* Mail timeout used by the file-queue */
int mail_timeout;


/* Global var for highest level on mail subjects */
int   _g_subject_level;
char _g_subject[SUBJECT_SIZE +2];


#endif
