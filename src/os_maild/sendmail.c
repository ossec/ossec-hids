/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic e-mailing operations (plain TCP / local sendmail). Not used when USE_SMTP_CURL is defined. */

#ifndef USE_SMTP_CURL

#include "shared.h"
#include "os_net/os_net.h"
#include "maild.h"
#include "mail_list.h"
#include "mail_utils.h"

/* Return codes (from SMTP server) */
#define VALIDBANNER     "220"
#define VALIDMAIL       "250"
#define VALIDDATA       "354"

/* Default values used to connect */
#define SMTP_DEFAULT_PORT   "25"
#define MAILFROM            "Mail From: <%s>\r\n"
#define RCPTTO              "Rcpt To: <%s>\r\n"
#define DATAMSG             "DATA\r\n"
#define FROM                "From: OSSEC HIDS <%s>\r\n"
#define TO                  "To: <%s>\r\n"
#define REPLYTO             "Reply-To: OSSEC HIDS <%s>\r\n"
/*#define CC                "Cc: <%s>\r\n"*/
#define SUBJECT             "Subject: %s\r\n"
#define ENDHEADER           "\r\n"
#define ENDDATA             "\r\n.\r\n"
#define QUITMSG             "QUIT\r\n"
#define XHEADER             "X-IDS-OSSEC: %s\r\n"

/* Error messages - Can be translated */
#define INTERNAL_ERROR  "os_maild (1760): ERROR: Memory/configuration error"
#define BANNER_ERROR    "os_sendmail(1762): WARN: Banner not received from server"
#define HELO_ERROR      "os_sendmail(1763): WARN: Hello not accepted by server"
#define FROM_ERROR      "os_sendmail(1764): WARN: Mail from not accepted by server"
#define TO_ERROR        "os_sendmail(1765): WARN: RCPT TO not accepted by server - '%s'."
#define DATA_ERROR      "os_sendmail(1766): WARN: DATA not accepted by server"
#define END_DATA_ERROR  "os_sendmail(1767): WARN: End of DATA not accepted by server"

#define MAIL_DEBUG_FLAG     0
#define MAIL_DEBUG(x,y,z) if(MAIL_DEBUG_FLAG) merror(x,y,z)

static int mail_gran_format(const MailConfig *mail, const int *gran_override,
                            unsigned int i)
{
    if (gran_override) {
        return gran_override[i];
    }
    if (mail->gran_set) {
        return mail->gran_set[i];
    }
    return 0;
}

static void free_mail_batch(MailNode *batch)
{
    MailNode *n;

    if (!batch) {
        return;
    }

    while (batch) {
        n = batch;
        batch = batch->next;
        FreeMail(n);
    }
}

static int sms_gran_format(const MailConfig *mail, const int *gran_override, int i)
{
    if (gran_override) {
        return gran_override[i];
    }
    if (mail->gran_set) {
        return mail->gran_set[i];
    }
    return 0;
}

/* Skip RCPT/header addresses with CR/LF; log once per send attempt. */
static int mail_skip_unsafe_recipient(const char *addr, int *warned)
{
    if (!addr || !mail_address_has_crlf(addr)) {
        return (0);
    }

    if (!*warned) {
        merror("%s: Skipping recipient with CR/LF in address (SMTP injection risk).",
               ARGV0);
        *warned = 1;
    }

    return (1);
}

static void mail_safe_header_addr(const char *addr, char *dst, size_t dst_size)
{
    mail_sanitize_header_value(addr, dst, dst_size);
}

static int mail_safe_envelope(const char *src, char *dst, size_t dst_size,
                              int *warned, const char *field)
{
    if (mail_safe_envelope_value(src, dst, dst_size) == 0) {
        return (0);
    }

    if (src && mail_address_has_crlf(src) && warned && !*warned) {
        merror("%s: Rejecting SMTP %s with CR/LF (SMTP injection risk).",
               ARGV0, field);
        *warned = 1;
    }

    return (-1);
}

static int sms_build_to_headers(MailConfig *mail, const int *gran_override,
                                char *final_to, size_t final_to_cap,
                                int *crlf_warned)
{
    char snd_msg[128];
    char safe_addr[256];
    int i;

    if (!mail->gran_to) {
        return (0);
    }

    final_to[0] = '\0';

    i = 0;
    while (mail->gran_to[i] != NULL) {
        if (sms_gran_format(mail, gran_override, i) != SMS_FORMAT) {
            i++;
            continue;
        }

        if (mail_skip_unsafe_recipient(mail->gran_to[i], crlf_warned)) {
            i++;
            continue;
        }

        memset(snd_msg, '\0', 128);
        mail_safe_header_addr(mail->gran_to[i], safe_addr, sizeof(safe_addr));
        snprintf(snd_msg, 127, TO, safe_addr);
        if (mail_append_header_line(final_to, final_to_cap, snd_msg) != 0) {
            merror("%s: SMS To header buffer full; remaining recipients omitted.",
                   ARGV0);
            break;
        }

        i++;
    }

    return (final_to[0] != '\0');
}

int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *sms_msg,
               const int *gran_override)
{
    FILE *sendmail = NULL;
    int socket = -1;
    char *msg;
    char snd_msg[128];
    char final_to[512];
    char safe_addr[256];
    int i;
    int crlf_warned = 0;

    if (!mail || !p || !sms_msg || !mail->smtpserver || !mail->from) {
        return (OS_INVALID);
    }

    final_to[0] = '\0';

    if (mail->smtpserver[0] == '/') {
        sendmail = popen(mail->smtpserver, "w");
        if (!sendmail) {
            return (OS_INVALID);
        }

        if (!sms_build_to_headers(mail, gran_override, final_to, sizeof(final_to),
                                  &crlf_warned)) {
            pclose(sendmail);
            return (OS_INVALID);
        }
    } else {
        socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, mail->smtpserver);
        if (socket < 0) {
            return (socket);
        }

        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        free(msg);

        memset(snd_msg, '\0', 128);
        if (mail->heloserver &&
            mail_safe_envelope(mail->heloserver, safe_addr, sizeof(safe_addr),
                               &crlf_warned, "HELO host") == 0) {
            snprintf(snd_msg, 127, "Helo %s\r\n", safe_addr);
        } else if (!mail->heloserver) {
            snprintf(snd_msg, 127, "Helo %s\r\n", "notify.ossec.net");
        } else {
            close(socket);
            return (OS_INVALID);
        }
        OS_SendTCP(socket, snd_msg);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);
                    msg = OS_RecvTCP(socket, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(socket);
                        return (OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(socket);
                    return (OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(socket);
                return (OS_INVALID);
            }
        }
        free(msg);

        memset(snd_msg, '\0', 128);
        if (mail_safe_envelope(mail->from, safe_addr, sizeof(safe_addr),
                               &crlf_warned, "MAIL FROM") != 0) {
            close(socket);
            return (OS_INVALID);
        }
        snprintf(snd_msg, 127, MAILFROM, safe_addr);
        OS_SendTCP(socket, snd_msg);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            merror(FROM_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        free(msg);

        final_to[0] = '\0';

        if (mail->gran_to) {
            i = 0;
            while (mail->gran_to[i] != NULL) {
                if (sms_gran_format(mail, gran_override, i) != SMS_FORMAT) {
                    i++;
                    continue;
                }

                if (mail_skip_unsafe_recipient(mail->gran_to[i], &crlf_warned)) {
                    i++;
                    continue;
                }

                memset(snd_msg, '\0', 128);
                snprintf(snd_msg, 127, RCPTTO, mail->gran_to[i]);
                OS_SendTCP(socket, snd_msg);
                msg = OS_RecvTCP(socket, OS_SIZE_1024);
                if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                    merror(TO_ERROR, mail->gran_to[i]);
                    if (msg) {
                        free(msg);
                    }
                    close(socket);
                    return (OS_INVALID);
                }
                free(msg);

                memset(snd_msg, '\0', 128);
                mail_safe_header_addr(mail->gran_to[i], safe_addr, sizeof(safe_addr));
                snprintf(snd_msg, 127, TO, safe_addr);
                if (mail_append_header_line(final_to, sizeof(final_to), snd_msg) != 0) {
                    merror("%s: SMS To header buffer full; remaining recipients omitted.",
                           ARGV0);
                    break;
                }

                i++;
            }
        }

        if (final_to[0] == '\0') {
            close(socket);
            return (OS_INVALID);
        }

        OS_SendTCP(socket, DATAMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
            merror(DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        free(msg);

        OS_SendTCP(socket, final_to);
    }

    memset(snd_msg, '\0', 128);
    if (mail_safe_envelope(mail->from, safe_addr, sizeof(safe_addr),
                           &crlf_warned, "From") != 0) {
        if (sendmail) {
            pclose(sendmail);
        } else if (socket >= 0) {
            close(socket);
        }
        return (OS_INVALID);
    }
    snprintf(snd_msg, 127, FROM, safe_addr);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    if (mail->reply_to) {
        memset(snd_msg, '\0', 128);
        if (mail_safe_envelope(mail->reply_to, safe_addr, sizeof(safe_addr),
                               &crlf_warned, "Reply-To") == 0) {
            snprintf(snd_msg, 127, REPLYTO, safe_addr);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(socket, snd_msg);
            }
        }
    }

    memset(snd_msg, '\0', 128);
#ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n", p);
#else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n", p);
#endif

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
        fprintf(sendmail, "%s", final_to);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    memset(snd_msg, '\0', 128);
    mail_safe_header_addr(sms_msg->subject, safe_addr, sizeof(safe_addr));
    snprintf(snd_msg, 127, SUBJECT, safe_addr);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
        fprintf(sendmail, ENDHEADER);
        fprintf(sendmail, "%s", sms_msg->body);

        if (pclose(sendmail) == -1) {
            merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
        }
    } else {
        OS_SendTCP(socket, snd_msg);
        OS_SendTCP(socket, ENDHEADER);
        OS_SendTCP(socket, sms_msg->body);

        OS_SendTCP(socket, ENDDATA);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if (mail->strict_checking && ((msg == NULL) || (!OS_Match(VALIDMAIL, msg)))) {
            merror(END_DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        if (msg) {
            free(msg);
        }

        OS_SendTCP(socket, QUITMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if (msg) {
            free(msg);
        }

        close(socket);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}

int OS_Sendmail(MailConfig *mail, struct tm *p, MailNode *batch,
                const int *gran_override, const char *group_subject,
                unsigned int group_subject_level)
{
    FILE *sendmail = NULL;
    int socket = -1;
    unsigned int i = 0;
    char *msg;
    char snd_msg[128];
    char safe_addr[256];
    int crlf_warned = 0;
    int valid_rcpt = 0;

    MailNode *mailmsg = batch;

    if (mailmsg == NULL) {
        merror("%s: No email to be sent. Inconsistent state.", ARGV0);
        return (OS_INVALID);
    }

    if (!mail->smtpserver || !mail->from) {
        free_mail_batch(batch);
        return (OS_INVALID);
    }

#define mail_send_fail(code) do { free_mail_batch(batch); return (code); } while (0)

    if (mail->smtpserver[0] == '/') {
        sendmail = popen(mail->smtpserver, "w");
        if (!sendmail) {
            mail_send_fail(OS_INVALID);
        }
    } else {
        /* Connect to the SMTP server */
        socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, mail->smtpserver);
        if (socket < 0) {
            mail_send_fail(socket);
        }

        /* Receive the banner */
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            mail_send_fail(OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
        free(msg);

        /* Send HELO message */
        memset(snd_msg, '\0', 128);
        if (mail->heloserver &&
            mail_safe_envelope(mail->heloserver, safe_addr, sizeof(safe_addr),
                               &crlf_warned, "HELO host") == 0) {
            snprintf(snd_msg, 127, "Helo %s\r\n", safe_addr);
        } else if (!mail->heloserver) {
            snprintf(snd_msg, 127, "Helo %s\r\n", "notify.ossec.net");
        } else {
            close(socket);
            mail_send_fail(OS_INVALID);
        }
        OS_SendTCP(socket, snd_msg);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                /* In some cases (with virus scans in the middle)
                 * we may get two banners. Check for that in here.
                 */
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);

                    /* Try again */
                    msg = OS_RecvTCP(socket, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(socket);
                        mail_send_fail(OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(socket);
                    mail_send_fail(OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(socket);
                mail_send_fail(OS_INVALID);
            }
        }

        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

        /* Build "Mail from" msg */
        memset(snd_msg, '\0', 128);
        if (mail_safe_envelope(mail->from, safe_addr, sizeof(safe_addr),
                               &crlf_warned, "MAIL FROM") != 0) {
            close(socket);
            mail_send_fail(OS_INVALID);
        }
        snprintf(snd_msg, 127, MAILFROM, safe_addr);
        OS_SendTCP(socket, snd_msg);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            merror(FROM_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            mail_send_fail(OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

        /* Build "RCPT TO" msg */
        i = 0;
        while (1) {
            if (mail->to[i] == NULL) {
                if (valid_rcpt == 0) {
                    merror(INTERNAL_ERROR);
                    close(socket);
                    mail_send_fail(OS_INVALID);
                }
                break;
            }
            if (mail_skip_unsafe_recipient(mail->to[i], &crlf_warned)) {
                i++;
                continue;
            }
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, RCPTTO, mail->to[i++]);
            valid_rcpt++;
            OS_SendTCP(socket, snd_msg);
            msg = OS_RecvTCP(socket, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(TO_ERROR, mail->to[i - 1]);
                if (msg) {
                    free(msg);
                }
                close(socket);
                mail_send_fail(OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);
        }

        /* Additional RCPT to */
        if (mail->gran_to) {
            i = 0;
            while (mail->gran_to[i] != NULL) {
                if (mail_gran_format(mail, gran_override, i) != FULL_FORMAT) {
                    i++;
                    continue;
                }

                if (mail_skip_unsafe_recipient(mail->gran_to[i], &crlf_warned)) {
                    i++;
                    continue;
                }

                memset(snd_msg, '\0', 128);
                snprintf(snd_msg, 127, RCPTTO, mail->gran_to[i]);
                OS_SendTCP(socket, snd_msg);
                msg = OS_RecvTCP(socket, OS_SIZE_1024);
                if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                    merror(TO_ERROR, mail->gran_to[i]);
                    if (msg) {
                        free(msg);
                    }

                    i++;
                    continue;
                }

                MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
                free(msg);
                i++;
                continue;
            }
        }

        /* Send the "DATA" msg */
        OS_SendTCP(socket, DATAMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
            merror(DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            mail_send_fail(OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
        free(msg);
    }

    /* Building "From" and "To" in the e-mail header */
    memset(snd_msg, '\0', 128);
    mail_safe_header_addr(mail->to[0], safe_addr, sizeof(safe_addr));
    if (safe_addr[0] == '\0') {
        if (sendmail) {
            pclose(sendmail);
        } else if (socket >= 0) {
            close(socket);
        }
        mail_send_fail(OS_INVALID);
    }
    snprintf(snd_msg, 127, TO, safe_addr);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    memset(snd_msg, '\0', 128);
    if (mail_safe_envelope(mail->from, safe_addr, sizeof(safe_addr),
                           &crlf_warned, "From") != 0) {
        if (sendmail) {
            pclose(sendmail);
        } else if (socket >= 0) {
            close(socket);
        }
        mail_send_fail(OS_INVALID);
    }
    snprintf(snd_msg, 127, FROM, safe_addr);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    /* Send reply-to if set */
    if (mail->reply_to) {
        memset(snd_msg, '\0', 128);
        if (mail_safe_envelope(mail->reply_to, safe_addr, sizeof(safe_addr),
                               &crlf_warned, "Reply-To") == 0) {
            snprintf(snd_msg, 127, REPLYTO, safe_addr);
            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(socket, snd_msg);
            }
        }
    }

    /* Add CCs */
    if (mail_has_cc_recipients(mail->to, 0)) {
        i = 1;
        while (1) {
            if (mail->to[i] == NULL) {
                break;
            }

            if (mail_skip_unsafe_recipient(mail->to[i], &crlf_warned)) {
                i++;
                continue;
            }

            memset(snd_msg, '\0', 128);
            mail_safe_header_addr(mail->to[i], safe_addr, sizeof(safe_addr));
            snprintf(snd_msg, 127, TO, safe_addr);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(socket, snd_msg);
            }

            i++;
        }
    }

    /* More CCs - from granular options */
    if (mail->gran_to) {
        i = 0;
        while (mail->gran_to[i] != NULL) {
            if (mail_gran_format(mail, gran_override, i) != FULL_FORMAT) {
                i++;
                continue;
            }

            if (mail_skip_unsafe_recipient(mail->gran_to[i], &crlf_warned)) {
                i++;
                continue;
            }

            memset(snd_msg, '\0', 128);
            mail_safe_header_addr(mail->gran_to[i], safe_addr, sizeof(safe_addr));
            snprintf(snd_msg, 127, TO, safe_addr);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(socket, snd_msg);
            }

            i++;
            continue;
        }
    }

    /* Send date */
    memset(snd_msg, '\0', 128);

    /* Solaris doesn't have the "%z", so we set the timezone to 0 */
#ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n", p);
#else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n", p);
#endif

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    if (mail->idsname) {
        /* Send server name header */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, XHEADER, mail->idsname);

        if (sendmail) {
            fprintf(sendmail, "%s", snd_msg);
        } else {
            OS_SendTCP(socket, snd_msg);
        }
    }

    /* Send subject */
    memset(snd_msg, '\0', 128);

    /* Use snapshotted grouped subject when provided */
    if (group_subject_level != 0 && group_subject && group_subject[0] != '\0') {
        mail_safe_header_addr(group_subject, safe_addr, sizeof(safe_addr));
    } else {
        mail_safe_header_addr(mailmsg->mail->subject, safe_addr, sizeof(safe_addr));
    }
    snprintf(snd_msg, 127, SUBJECT, safe_addr);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
        fprintf(sendmail, ENDHEADER);
    } else {
        OS_SendTCP(socket, snd_msg);
        OS_SendTCP(socket, ENDHEADER);
    }

    /* Send body */

    /* Send multiple emails together if we have to */
    do {
        if (sendmail) {
            fprintf(sendmail, "%s", mailmsg->mail->body);
        } else {
            OS_SendTCP(socket, mailmsg->mail->body);
        }
        mailmsg = mailmsg->next;
    } while (mailmsg);

    free_mail_batch(batch);
    batch = NULL;

    if (sendmail) {
        if (pclose(sendmail) == -1) {
            merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
        }
    } else {
        /* Send end of data \r\n.\r\n */
        OS_SendTCP(socket, ENDDATA);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if (mail->strict_checking && ((msg == NULL) || (!OS_Match(VALIDMAIL, msg)))) {
            merror(END_DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }

        /* Check msg, since it may be null */
        if (msg) {
            free(msg);
        }

        /* Quit and close socket */
        OS_SendTCP(socket, QUITMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);

        if (msg) {
            free(msg);
        }

        close(socket);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}

#endif /* !USE_SMTP_CURL */
