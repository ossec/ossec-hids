/* Copyright (C) 2019 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic e-mailing operations */

#include <event.h>

#include "shared.h"
#include "os_net/os_net.h"
#include "maild.h"
#include "mail_list.h"
#include "os_dns/os_dns.h"

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

int os_sock;

void os_sendmail_cb(int fd, short ev, void *arg) {
    if (fd) { }
    if (ev) {}

    /* Have to get the *arg stuff */
    ssize_t n;
    struct imsg imsg;
    struct imsgbuf *ibuf = (struct imsgbuf *)arg;

    if ((n = imsg_read(ibuf) == -1 && errno != EAGAIN)) {
        ErrorExit("%s: ERROR: imsg_read() failed: %s", ARGV0, strerror(errno));
    }
    if (n == 0) {
        debug2("%s: DEBUG: n == 0", ARGV0);
        //return; //XXX
    }
    if (n == EAGAIN) {
        debug2("%s: DEBUG: n == EAGAIN", ARGV0);
        return; //XXX
    }

    if ((n = imsg_get(ibuf, &imsg)) == -1) {
        merror("%s: ERROR: imsg_get() failed: %s", ARGV0, strerror(errno));
        return;
    }
    if (n == 0) {
        debug2("%s: DEBUG: n == 0", ARGV0);
        return;
    }

    switch(imsg.hdr.type) {
        case DNS_RESP:
            os_sock = imsg.fd;
            break;
        case DNS_FAIL:
            merror("%s: ERROR: DNS failure for smtpserver", ARGV0);
            break;;
        default:
            merror("%s: ERROR Wrong imsg type.", ARGV0);
            break;
    }



    return;
}



int OS_Sendmail(MailConfig *mail, struct tm *p)
{
    FILE *sendmail = NULL;
    os_sock = -1;
    unsigned int i = 0;
    char *msg;
    char snd_msg[128];

    MailNode *mailmsg;

    /* If there is no sms message, attempt to get from the email list */
    mailmsg = OS_PopLastMail();

    if (mailmsg == NULL) {
        merror("%s: No email to be sent. Inconsistent state.", ARGV0);
        return (OS_INVALID);
    }


    if (mail->smtpserver[0] == '/') {
        sendmail = popen(mail->smtpserver, "w");
        if (!sendmail) {
            return (OS_INVALID);
        }
    } else {
        /* Try to use os_dns =] */

        /* setup the libevent stuff */
        struct event_base *eb;
        eb = event_init();
        if (!eb) {
            ErrorExit("%s: ERROR: event_init() failed.", ARGV0);
        }

        struct event ev_accept;
        event_set(&ev_accept, mail->ibuf.fd, EV_READ, os_sendmail_cb, &mail->ibuf);
        event_add(&ev_accept, NULL);

        ssize_t n;
        
        struct os_dns_request dnsr; 
        dnsr.hostname = mail->smtpserver;
        dnsr.hname_len = strnlen(dnsr.hostname, 256);
        dnsr.caller = ARGV0;
        dnsr.protocol = "smtp";

        if ((imsg_compose(&mail->ibuf, DNS_REQ, 0, 0, -1, &dnsr, sizeof(&dnsr))) == -1) {
            merror("%s: ERROR: imsg_compose() error: %s", ARGV0, strerror(errno));
        }

        if ((n = msgbuf_write(&mail->ibuf.w)) == -1 && errno != EAGAIN) {
            merror("%s: ERROR: msgbuf_write() error: %s", ARGV0, strerror(errno));
        }
        if (n == 0) {
            debug2("%s: INFO: (write) n == 0", ARGV0);
        }

        event_dispatch();

        if (os_sock <= 0) {
            ErrorExit("ossec-maild: ERROR: No socket.");
        }

        /* Receive the banner */
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
        free(msg);

        /* Send HELO message */
        memset(snd_msg, '\0', 128);
        if (mail->heloserver) {
            snprintf(snd_msg, 127, "Helo %s\r\n", mail->heloserver);
        } else {
            snprintf(snd_msg, 127, "Helo %s\r\n", "notify.ossec.net");
        }
        OS_SendTCP(os_sock, snd_msg);
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                /* In some cases (with virus scans in the middle)
                 * we may get two banners. Check for that in here.
                 */
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);

                    /* Try again */
                    msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(os_sock);
                        return (OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(os_sock);
                    return (OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(os_sock);
                return (OS_INVALID);
            }
        }

        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

        /* Build "Mail from" msg */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, MAILFROM, mail->from);
        OS_SendTCP(os_sock, snd_msg);
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            merror(FROM_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

        /* Build "RCPT TO" msg */
        while (1) {
            if (mail->to[i] == NULL) {
                if (i == 0) {
                    merror(INTERNAL_ERROR);
                    close(os_sock);
                    return (OS_INVALID);
                }
                break;
            }
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, RCPTTO, mail->to[i++]);
            OS_SendTCP(os_sock, snd_msg);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(TO_ERROR, mail->to[i - 1]);
                if (msg) {
                    free(msg);
                }
                close(os_sock);
                return (OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);
        }

        /* Additional RCPT to */
        if (mail->gran_to) {
            i = 0;
            while (mail->gran_to[i] != NULL) {
                if (mail->gran_set[i] != FULL_FORMAT) {
                    i++;
                    continue;
                }

                memset(snd_msg, '\0', 128);
                snprintf(snd_msg, 127, RCPTTO, mail->gran_to[i]);
                OS_SendTCP(os_sock, snd_msg);
                msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
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
        OS_SendTCP(os_sock, DATAMSG);
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
            merror(DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
        free(msg);
    }

    /* Building "From" and "To" in the e-mail header */
    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, TO, mail->to[0]);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(os_sock, snd_msg);
    }

    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, FROM, mail->from);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(os_sock, snd_msg);
    }

    /* Send reply-to if set */
    if (mail->reply_to){
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, REPLYTO, mail->reply_to);
        if (sendmail) {
            fprintf(sendmail, "%s", snd_msg);
        } else {
            OS_SendTCP(os_sock, snd_msg);
        }
    }

    /* Add CCs */
    if (mail->to[1]) {
        i = 1;
        while (1) {
            if (mail->to[i] == NULL) {
                break;
            }

            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, TO, mail->to[i]);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(os_sock, snd_msg);
            }

            i++;
        }
    }

    /* More CCs - from granular options */
    if (mail->gran_to) {
        i = 0;
        while (mail->gran_to[i] != NULL) {
            if (mail->gran_set[i] != FULL_FORMAT) {
                i++;
                continue;
            }

            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, TO, mail->gran_to[i]);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(os_sock, snd_msg);
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
        OS_SendTCP(os_sock, snd_msg);
    }

    if (mail->idsname) {
        /* Send server name header */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, XHEADER, mail->idsname);

        if (sendmail) {
            fprintf(sendmail, "%s", snd_msg);
        } else {
            OS_SendTCP(os_sock, snd_msg);
        }
    }

    /* Send subject */
    memset(snd_msg, '\0', 128);

    /* Check if global subject is available */
    if ((_g_subject_level != 0) && (_g_subject[0] != '\0')) {
        snprintf(snd_msg, 127, SUBJECT, _g_subject);

        /* Clear global values */
        _g_subject[0] = '\0';
        _g_subject_level = 0;
    } else {
        snprintf(snd_msg, 127, SUBJECT, mailmsg->mail->subject);
    }

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
        fprintf(sendmail, ENDHEADER);
    } else {
        OS_SendTCP(os_sock, snd_msg);
        OS_SendTCP(os_sock, ENDHEADER);
    }

    /* Send body */

    /* Send multiple emails together if we have to */
    do {
        if (sendmail) {
            fprintf(sendmail, "%s", mailmsg->mail->body);
        } else {
            OS_SendTCP(os_sock, mailmsg->mail->body);
        }
        mailmsg = OS_PopLastMail();
    } while (mailmsg);

    if (sendmail) {
        if (pclose(sendmail) == -1) {
            merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
        }
    } else {
        /* Send end of data \r\n.\r\n */
        OS_SendTCP(os_sock, ENDDATA);
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if (mail->strict_checking && ((msg == NULL) || (!OS_Match(VALIDMAIL, msg)))) {
            merror(END_DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }

        /* Check msg, since it may be null */
        if (msg) {
            free(msg);
        }

        /* Quit and close os_sock */
        OS_SendTCP(os_sock, QUITMSG);
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);

        if (msg) {
            free(msg);
        }

        close(os_sock);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}
