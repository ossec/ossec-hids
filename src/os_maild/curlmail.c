/* Copyright (C) Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * SMTP send via libcurl (TLS + AUTH). Built only when USE_SMTP_CURL is defined.
 *
 * On curl_easy_perform failure, errors are logged via merror with:
 *   - A TLS category line when verification fails (grep "SMTP TLS verification failed").
 *   - curl_easy_strerror(res) and CURLOPT_ERRORBUFFER detail when libcurl provides it.
 *   - CURLINFO_SSL_VERIFYRESULT for TLS verification failures (meaning is backend-specific).
 *   - CURLINFO_OS_ERRNO when the platform errno is set (e.g. connection failures).
 * Mail bodies and credentials are not logged here.
 */

#ifdef USE_SMTP_CURL

#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "shared.h"
#include "maild.h"
#include "mail_list.h"
#include "mail_utils.h"

#define HEADER_MAX      2048
#define SMTP_URL_MAX    512
#define HOSTNAME_MAX    253
#define CONNECT_TIMEOUT 30
#define TRANSFER_TIMEOUT 120

typedef struct _smtp_payload_ctx {
    const char *header;
    size_t header_len;
    size_t header_sent;
    MailNode *first_node;
    MailNode *current_node;
    size_t body_sent;
} smtp_payload_ctx;

/* Validate an SMTP host string.
 * Accept:
 *   - Regular hostnames: alphanumeric, hyphen, dot, up to HOSTNAME_MAX chars.
 *   - IPv6 literals, with or without brackets: [2001:db8::1], 2001:db8::1, etc.
 *     For IPv6 literals we allow hex digits, ':', and '.', and require at least one ':'.
 */
static int is_valid_smtp_host(const char *host)
{
    size_t len;
    const char *p;
    const char *end;
    size_t i;
    int has_colon = 0;

    if (!host) {
        return 0;
    }

    len = strlen(host);
    if (len == 0) {
        return 0;
    }

    /* Handle optional brackets for IPv6 literals: [addr] */
    if (host[0] == '[' && host[len - 1] == ']') {
        /* Inner content must be non-empty and within HOSTNAME_MAX */
        if (len <= 2 || (len - 2) > HOSTNAME_MAX) {
            return 0;
        }
        p = host + 1;
        end = host + len - 1;
    } else {
        if (len > HOSTNAME_MAX) {
            return 0;
        }
        p = host;
        end = host + len;
    }

    /* First, try strict hostname rules: [A-Za-z0-9.-]+ */
    for (i = 0; p + i < end; i++) {
        unsigned char c = (unsigned char)p[i];
        if (!isalnum(c) && c != '-' && c != '.') {
            break;
        }
    }
    if (p + i == end && i > 0) {
        /* Entire string is a valid hostname */
        return 1;
    }

    /* Fallback: allow IPv6 literals (possibly with embedded IPv4). */
    for (i = 0; p + i < end; i++) {
        unsigned char c = (unsigned char)p[i];

        if (c == ':') {
            has_colon = 1;
            continue;
        }

        /* Allow '.' for IPv4-embedded IPv6 */
        if (c == '.') {
            continue;
        }

        if (!isxdigit(c)) {
            return 0;
        }
    }

    /* Must contain at least one ':' to be considered IPv6. */
    return (i > 0 && has_colon);
}

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
    smtp_payload_ctx *ctx = (smtp_payload_ctx *)userp;
    size_t want;
    size_t sent = 0;

    if (size == 0 || nmemb > SIZE_MAX / size) {
        return 0;
    }
    want = size * nmemb;

    if (ctx->header_sent < ctx->header_len) {
        size_t left = ctx->header_len - ctx->header_sent;
        sent = (want < left) ? want : left;
        memcpy(ptr, ctx->header + ctx->header_sent, sent);
        ctx->header_sent += sent;
        return sent;
    }

    if (!ctx->current_node) {
        ctx->current_node = ctx->first_node;
        ctx->body_sent = 0;
    }

    while (ctx->current_node) {
        const char *body = ctx->current_node->mail->body ? ctx->current_node->mail->body : "";
        size_t body_len = strlen(body);

        if (ctx->body_sent < body_len) {
            size_t left = body_len - ctx->body_sent;
            sent = (want < left) ? want : left;
            memcpy(ptr, body + ctx->body_sent, sent);
            ctx->body_sent += sent;
            return sent;
        }

        /* Current body finished, advance through detached batch */
        ctx->current_node = ctx->current_node->next;
        ctx->body_sent = 0;
    }

    return 0;
}

/* True if res indicates server certificate / chain verification problems. */
static int curlcode_is_tls_peer_failure(CURLcode res)
{
    if (res == CURLE_PEER_FAILED_VERIFICATION || res == CURLE_SSL_CERTPROBLEM) {
        return 1;
    }
#ifdef CURLE_SSL_INVALIDCERTSTATUS
    if (res == CURLE_SSL_INVALIDCERTSTATUS) {
        return 1;
    }
#endif
#ifdef CURLE_SSL_ISSUER_ERROR
    if (res == CURLE_SSL_ISSUER_ERROR) {
        return 1;
    }
#endif
    return 0;
}

/* Log libcurl failure after curl_easy_perform; errbuf is CURLOPT_ERRORBUFFER storage. */
static void log_smtp_curl_perform_failure(CURL *curl, CURLcode res, const char *errbuf)
{
    if (curlcode_is_tls_peer_failure(res)) {
        merror("%s: SMTP TLS verification failed (see following curl messages).", ARGV0);
    }

    merror("%s: curl_easy_perform failed: %s", ARGV0, curl_easy_strerror(res));

    if (errbuf != NULL && errbuf[0] != '\0') {
        merror("%s: curl error detail: %s", ARGV0, errbuf);
    }

    if (curl != NULL && curlcode_is_tls_peer_failure(res)) {
        long verify_result = 0;
        if (curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_result) == CURLE_OK) {
            merror("%s: CURLINFO_SSL_VERIFYRESULT=%ld (meaning depends on TLS backend).", ARGV0, verify_result);
        }
    }

    if (curl != NULL) {
        long oserrno = 0;
        if (curl_easy_getinfo(curl, CURLINFO_OS_ERRNO, &oserrno) == CURLE_OK && oserrno != 0) {
            if (oserrno > 0 && oserrno <= INT_MAX) {
                int e = (int)oserrno;
                merror("%s: curl OS errno %d: %s", ARGV0, e, strerror(e));
            } else {
                merror("%s: curl OS errno %ld (outside int range for strerror).", ARGV0, oserrno);
            }
        }
    }
}

static void free_mail_batch(MailNode *batch)
{
    MailNode *n;

    while (batch) {
        n = batch;
        batch = batch->next;
        FreeMail(n);
    }
}

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

static int send_one_mail(CURL *curl, MailConfig *mail, struct tm *p,
                         MailNode *mailmsg, const int *gran_override,
                         const char *group_subject,
                         unsigned int group_subject_level, int sms_only)
{
    struct curl_slist *recipients = NULL;
    struct curl_slist *resolve_list = NULL;
    char url[SMTP_URL_MAX];
    char header_buf[HEADER_MAX];
    char date_buf[64];
    char message_id[128];
    char hostname[256];
    char sanitized_subject[512];
    char sanitized_from[384];
    char sanitized_to[384];
    char curl_errbuf[CURL_ERROR_SIZE];
    smtp_payload_ctx ctx;
    CURLcode res;
    unsigned int i;
    int ret = -1;

    curl_easy_reset(curl);

    if (!mail->smtpserver || !mail->from) {
        merror("%s: Incomplete mail config (smtp_server, email_from).", ARGV0);
        goto done;
    }

    if (!sms_only && (!mail->to || !mail->to[0])) {
        merror("%s: Incomplete mail config (email_to).", ARGV0);
        goto done;
    }

    if (!is_valid_smtp_host(mail->smtpserver)) {
        merror("%s: Invalid smtp_server (hostname only, no path or invalid chars).", ARGV0);
        goto done;
    }

    if (mail->authsmtp && (!mail->smtp_user || !mail->smtp_pass)) {
        merror("%s: auth_smtp=yes requires smtp_user and smtp_password to be set.", ARGV0);
        goto done;
    }

    /* Build URL: optional smtp_port overrides defaults (465/587/25 per mode) */
    {
        int port = mail->smtp_port;
        int n;
        if (port <= 0 || port > 65535) {
            if (mail->securesmtp) {
                port = 465;
            } else if (mail->authsmtp) {
                port = 587;
            } else {
                port = 25;
            }
        }
        if (mail->securesmtp) {
            n = snprintf(url, sizeof(url), "smtps://%s:%d", mail->smtpserver, port);
        } else {
            n = snprintf(url, sizeof(url), "smtp://%s:%d", mail->smtpserver, port);
        }
        if (n < 0 || (size_t)n >= sizeof(url)) {
            merror("%s: smtp_server or URL too long (truncation).", ARGV0);
            goto done;
        }
        /* Pre-resolved IP for chroot (no DNS inside jail); hostname:port:ip for CURLOPT_RESOLVE */
        if (mail->smtpserver_resolved) {
            char resolve_buf[384];
            if (strchr(mail->smtpserver_resolved, ':')) {
                n = snprintf(resolve_buf, sizeof(resolve_buf), "%s:%d:[%s]", mail->smtpserver, port, mail->smtpserver_resolved);
            } else {
                n = snprintf(resolve_buf, sizeof(resolve_buf), "%s:%d:%s", mail->smtpserver, port, mail->smtpserver_resolved);
            }
            if (n < 0 || (size_t)n >= sizeof(resolve_buf)) {
                merror("%s: smtp_server or resolved IP too long for CURLOPT_RESOLVE (truncation).", ARGV0);
                goto done;
            }
            resolve_list = curl_slist_append(NULL, resolve_buf);
            if (!resolve_list) {
                merror("%s: Failed to build resolve list for chroot (CURLOPT_RESOLVE).", ARGV0);
                goto done;
            }
            curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
        }
    }

    if (!mail->securesmtp && !mail->authsmtp) {
        verbose("%s: Sending mail via unencrypted SMTP (smtp://%s:%d).", ARGV0, mail->smtpserver,
                mail->smtp_port > 0 ? mail->smtp_port : 25);
    }

    /* Recipient list: mail->to[] and mail->gran_to[] (FULL_FORMAT only).
     * Reject any recipient containing CR/LF to prevent SMTP command injection
     * (older libcurl may not sanitize CURLOPT_MAIL_RCPT). Use a temp so on
     * append failure we keep the list and free it in done. */
    {
        struct curl_slist *new_node;
        if (!sms_only) {
            for (i = 0; mail->to[i] != NULL; i++) {
                if (mail_address_has_crlf(mail->to[i])) {
                    merror("%s: Skipping recipient with invalid CR/LF (SMTP injection attempt or misconfiguration).", ARGV0);
                    continue;
                }
                new_node = curl_slist_append(recipients, mail->to[i]);
                if (!new_node) {
                    merror("%s: Failed to append recipient.", ARGV0);
                    goto done;
                }
                recipients = new_node;
            }
        }
        if (mail->gran_to) {
            for (i = 0; mail->gran_to[i] != NULL; i++) {
                int fmt = mail_gran_format(mail, gran_override, i);

                if (sms_only) {
                    if (fmt != SMS_FORMAT) {
                        continue;
                    }
                } else if (fmt != FULL_FORMAT) {
                    continue;
                }

                if (mail_address_has_crlf(mail->gran_to[i])) {
                    merror("%s: Skipping granular recipient with invalid CR/LF.", ARGV0);
                    continue;
                }
                new_node = curl_slist_append(recipients, mail->gran_to[i]);
                if (!new_node) {
                    merror("%s: Failed to append granular recipient.", ARGV0);
                    goto done;
                }
                recipients = new_node;
            }
        }
    }

    if (!recipients) {
        merror("%s: No recipients.", ARGV0);
        goto done;
    }

    hostname[0] = '\0';
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "localhost", sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
    } else {
        hostname[sizeof(hostname) - 1] = '\0';
    }
    strftime(message_id, sizeof(message_id), "%Y%m%d%H%M%S.%z", p);
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %T %z", p);

    /* Subject: use snapshotted grouped subject when provided. */
    {
        const char *raw_subject;

        if (group_subject_level != 0 && group_subject && group_subject[0] != '\0') {
            raw_subject = group_subject;
        } else if (mailmsg->mail->subject) {
            raw_subject = mailmsg->mail->subject;
        } else {
            raw_subject = "";
        }

        mail_sanitize_header_value(raw_subject, sanitized_subject, sizeof(sanitized_subject));
    }

    mail_sanitize_header_value(mail->from, sanitized_from, sizeof(sanitized_from));
    if (sms_only && mail->gran_to) {
        const char *sms_to = NULL;

        for (i = 0; mail->gran_to[i] != NULL; i++) {
            if (mail_gran_format(mail, gran_override, i) == SMS_FORMAT) {
                sms_to = mail->gran_to[i];
                break;
            }
        }
        if (!sms_to) {
            merror("%s: No SMS granular recipients.", ARGV0);
            goto done;
        }
        mail_sanitize_header_value(sms_to, sanitized_to, sizeof(sanitized_to));
    } else {
        mail_sanitize_header_value(mail->to[0], sanitized_to, sizeof(sanitized_to));
    }

    /* Optional headers: CC, Reply-To, and X-IDS-OSSEC. */
    {
        char cc_header_line[HEADER_MAX];
        char replyto_header_line[HEADER_MAX];
        char sanitized_idsname[HEADER_MAX];
        int n;
        size_t i;

        cc_header_line[0] = '\0';
        replyto_header_line[0] = '\0';

        /* Build CC header from additional recipients (mail->to[1..]). */
        if (mail_has_cc_recipients(mail->to, sms_only)) {
            char cc_value[HEADER_MAX];
            size_t cc_len = 0;

            cc_value[0] = '\0';

            for (i = 1; mail->to[i] != NULL; ++i) {
                char sanitized_cc[HEADER_MAX];
                size_t addr_len;

                mail_sanitize_header_value(mail->to[i], sanitized_cc, sizeof(sanitized_cc));
                addr_len = strlen(sanitized_cc);

                if (addr_len == 0) {
                    continue;
                }

                /* Add comma+space between multiple CC addresses. */
                if (cc_len > 0) {
                    if (cc_len + 2 >= sizeof(cc_value)) {
                        break;
                    }
                    cc_value[cc_len++] = ',';
                    cc_value[cc_len++] = ' ';
                }

                if (cc_len + addr_len >= sizeof(cc_value)) {
                    break;
                }

                memcpy(cc_value + cc_len, sanitized_cc, addr_len);
                cc_len += addr_len;
                cc_value[cc_len] = '\0';
            }

            if (cc_len > 0) {
                (void)snprintf(cc_header_line, sizeof(cc_header_line),
                               "Cc: %s\r\n", cc_value);
            }
        }

        /* Optional Reply-To header, if configured in the mail structure. */
        if (mail->reply_to) {
            char sanitized_reply_to[HEADER_MAX];

            mail_sanitize_header_value(mail->reply_to, sanitized_reply_to, sizeof(sanitized_reply_to));
            if (sanitized_reply_to[0] != '\0') {
                (void)snprintf(replyto_header_line, sizeof(replyto_header_line),
                               "Reply-To: %s\r\n", sanitized_reply_to);
            }
        }

        /* X-IDS-OSSEC header from mail->idsname, matching legacy behavior. */
        mail_sanitize_header_value(mail->idsname ? mail->idsname : "",
                              sanitized_idsname, sizeof(sanitized_idsname));

        n = snprintf(header_buf, sizeof(header_buf),
                     "Date: %s\r\n"
                     "To: %s\r\n"
                     "%s"
                     "From: %s\r\n"
                     "%s"
                     "Message-ID: <%s@%s>\r\n"
                     "X-IDS-OSSEC: %s\r\n"
                     "Subject: %s\r\n"
                     "\r\n",
                     date_buf,
                     sanitized_to,
                     cc_header_line,
                     sanitized_from,
                     replyto_header_line,
                     message_id,
                     hostname,
                     sanitized_idsname,
                     sanitized_subject);
        if (n < 0 || (size_t)n >= sizeof(header_buf)) {
            merror("%s: Email header truncated (subject/from/to too long).", ARGV0);
            goto done;
        }
    }

    ctx.header = header_buf;
    ctx.header_len = strlen(header_buf);
    ctx.header_sent = 0;
    ctx.first_node = mailmsg;
    ctx.current_node = NULL;
    ctx.body_sent = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, sanitized_from);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    /* Do not use alarm() for timeouts; ossec-maild uses SIGTERM/SIGHUP and may use alarm() */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)TRANSFER_TIMEOUT);
    if (mail->smtp_tls_verify) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        verbose("%s: SMTP TLS certificate verification disabled (smtp_tls_verify=no).", ARGV0);
    }
    /* No CURLOPT_VERBOSE - do not log to stderr */
    /* No CURLOPT_CAINFO - use system default CA bundle when verifying */

    if (mail->authsmtp && mail->smtp_user && mail->smtp_pass) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, mail->smtp_user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, mail->smtp_pass);
        /* Require TLS when using AUTH so credentials are not sent in plaintext */
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    }

    if (mail->securesmtp) {
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    }

    memset(curl_errbuf, 0, sizeof(curl_errbuf));
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_smtp_curl_perform_failure(curl, res, curl_errbuf);
        goto done;
    }

    ret = 0;
done:
    curl_slist_free_all(recipients);
    curl_slist_free_all(resolve_list);
    if (!sms_only) {
        free_mail_batch(mailmsg);
    }
    return ret;
}

int OS_Sendmail(MailConfig *mail, struct tm *p, MailNode *batch,
                const int *gran_override, const char *group_subject,
                unsigned int group_subject_level)
{
    CURL *curl = NULL;
    int ret = 0;

    if (!mail || !p || !batch) {
        return (OS_INVALID);
    }

    if (mail->smtpserver && mail->smtpserver[0] == '/') {
        /* Local sendmail path (e.g. /usr/sbin/sendmail) is not supported in USE_SMTP_CURL builds. */
        merror("%s: Invalid smtp_server configuration: local sendmail paths are not supported when built with USE_SMTP_CURL. Please configure smtp_server as an SMTP host[:port].", ARGV0);
        free_mail_batch(batch);
        return (OS_INVALID);
    }

    curl = curl_easy_init();
    if (!curl) {
        merror("%s: curl_easy_init failed.", ARGV0);
        free_mail_batch(batch);
        return (OS_INVALID);
    }

    if (send_one_mail(curl, mail, p, batch, gran_override, group_subject,
                      group_subject_level, 0) < 0) {
        ret = OS_INVALID;
    }

    curl_easy_cleanup(curl);
    return ret;
}

int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *sms_msg,
               const int *gran_override)
{
    CURL *curl = NULL;
    MailNode node;
    int ret = 0;

    if (!mail || !p || !sms_msg) {
        return (OS_INVALID);
    }

    if (mail->smtpserver && mail->smtpserver[0] == '/') {
        merror("%s: Invalid smtp_server configuration: local sendmail paths are not supported when built with USE_SMTP_CURL. Please configure smtp_server as an SMTP host[:port].", ARGV0);
        return (OS_INVALID);
    }

    node.mail = sms_msg;
    node.next = NULL;
    node.prev = NULL;

    curl = curl_easy_init();
    if (!curl) {
        merror("%s: curl_easy_init failed.", ARGV0);
        return (OS_INVALID);
    }

    if (send_one_mail(curl, mail, p, &node, gran_override, NULL, 0, 1) < 0) {
        ret = OS_INVALID;
    }

    curl_easy_cleanup(curl);
    return ret;
}

#endif /* USE_SMTP_CURL */
