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

#define HEADER_MAX      2048
#define SMTP_URL_MAX    512
#define HOSTNAME_MAX    253
#define CONNECT_TIMEOUT 30
#define TRANSFER_TIMEOUT 120

typedef struct _smtp_payload_ctx {
    const char *header;
    size_t header_len;
    size_t header_sent;
    const char *body;
    size_t body_len;
    size_t body_sent;
} smtp_payload_ctx;

/* Copy at most dst_size-1 chars from src into dst, stripping CR/LF to prevent header injection. */
static void sanitize_header_value(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    while (src[0] && j < dst_size - 1) {
        if (src[0] != '\r' && src[0] != '\n') {
            dst[j++] = src[0];
        }
        src++;
    }
    dst[j] = '\0';
}

/* Allow only hostname-safe chars (alphanumeric, hyphen, dot). Reject empty and overlength. */
static int is_valid_smtp_host(const char *host)
{
    size_t n = 0;
    if (!host || !host[0]) return 0;
    for (; host[n] && n <= HOSTNAME_MAX; n++) {
        if (!isalnum((unsigned char)host[n]) && host[n] != '-' && host[n] != '.') {
            return 0;
        }
    }
    return (host[n] == '\0' && n > 0 && n <= HOSTNAME_MAX);
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

    if (ctx->body_sent < ctx->body_len) {
        size_t left = ctx->body_len - ctx->body_sent;
        sent = (want < left) ? want : left;
        memcpy(ptr, ctx->body + ctx->body_sent, sent);
        ctx->body_sent += sent;
        return sent;
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

static int send_one_mail(CURL *curl, MailConfig *mail, struct tm *p, MailMsg *msg)
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
    size_t body_len;
    int ret = -1;

    curl_easy_reset(curl);

    if (!mail->smtpserver || !mail->from || !mail->to || !mail->to[0]) {
        merror("%s: Incomplete mail config (smtp_server, email_from, email_to).", ARGV0);
        return -1;
    }

    if (!is_valid_smtp_host(mail->smtpserver)) {
        merror("%s: Invalid smtp_server (hostname only, no path or invalid chars).", ARGV0);
        return -1;
    }

    if (mail->authsmtp && (!mail->smtp_user || !mail->smtp_pass)) {
        merror("%s: auth_smtp=yes requires smtp_user and smtp_password to be set.", ARGV0);
        return -1;
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
            return -1;
        }
        /* Pre-resolved IP for chroot (no DNS inside jail); hostname:port:ip for CURLOPT_RESOLVE */
        if (mail->smtpserver_resolved) {
            char resolve_buf[384];
            n = snprintf(resolve_buf, sizeof(resolve_buf), "%s:%d:%s", mail->smtpserver, port, mail->smtpserver_resolved);
            if (n < 0 || (size_t)n >= sizeof(resolve_buf)) {
                merror("%s: smtp_server or resolved IP too long for CURLOPT_RESOLVE (truncation).", ARGV0);
                return -1;
            }
            resolve_list = curl_slist_append(NULL, resolve_buf);
            if (!resolve_list) {
                merror("%s: Failed to build resolve list for chroot (CURLOPT_RESOLVE).", ARGV0);
                return -1;
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
        for (i = 0; mail->to[i] != NULL; i++) {
            if (strchr(mail->to[i], '\r') || strchr(mail->to[i], '\n')) {
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
        if (mail->gran_to && mail->gran_set) {
            for (i = 0; mail->gran_to[i] != NULL; i++) {
                if (mail->gran_set[i] == FULL_FORMAT) {
                    if (strchr(mail->gran_to[i], '\r') || strchr(mail->gran_to[i], '\n')) {
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

    sanitize_header_value(msg->subject ? msg->subject : "", sanitized_subject, sizeof(sanitized_subject));
    sanitize_header_value(mail->from, sanitized_from, sizeof(sanitized_from));
    sanitize_header_value(mail->to[0], sanitized_to, sizeof(sanitized_to));

    body_len = msg->body ? strlen(msg->body) : 0;
    {
        int n = snprintf(header_buf, sizeof(header_buf),
                         "Date: %s\r\n"
                         "To: %s\r\n"
                         "From: %s\r\n"
                         "Message-ID: <%s@%s>\r\n"
                         "Subject: %s\r\n"
                         "\r\n",
                         date_buf,
                         sanitized_to,
                         sanitized_from,
                         message_id,
                         hostname,
                         sanitized_subject);
        if (n < 0 || (size_t)n >= sizeof(header_buf)) {
            merror("%s: Email header truncated (subject/from/to too long).", ARGV0);
            goto done;
        }
    }

    ctx.header = header_buf;
    ctx.header_len = strlen(header_buf);
    ctx.header_sent = 0;
    ctx.body = msg->body ? msg->body : "";
    ctx.body_len = body_len;
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
    /* Explicit TLS verification so behavior is not dependent on libcurl defaults */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    /* No CURLOPT_VERBOSE - do not log to stderr */
    /* No CURLOPT_CAINFO - use system default CA bundle */

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
    /* message_id is date+hostname only, no secrets */
    return ret;
}

int OS_Sendmail(MailConfig *mail, struct tm *p)
{
    CURL *curl = NULL;
    MailNode *mailmsg;
    int ret = 0;

    if (!mail || !p) {
        return (OS_INVALID);
    }

    if (mail->smtpserver && mail->smtpserver[0] == '/') {
        /* Local sendmail path not supported in curl build; would need fallback to plain path */
        merror("%s: Local sendmail path not supported when built with USE_CURL.", ARGV0);
        return (OS_INVALID);
    }

    curl = curl_easy_init();
    if (!curl) {
        merror("%s: curl_easy_init failed.", ARGV0);
        return (OS_INVALID);
    }

    while ((mailmsg = OS_PopLastMail()) != NULL) {
        if (send_one_mail(curl, mail, p, mailmsg->mail) < 0) {
            ret = OS_INVALID;
        }
        FreeMail(mailmsg);
    }

    curl_easy_cleanup(curl);
    return ret;
}

#endif /* USE_SMTP_CURL */
