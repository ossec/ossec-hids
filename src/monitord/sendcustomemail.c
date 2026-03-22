/* Copyright (C) 2026 Atomicorp, Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"
#include "os_net/os_net.h"

#ifdef USE_SMTP_CURL
#include <curl/curl.h>

struct custom_payload_ctx {
    char *header;
    size_t header_pos;
    FILE *body_fp;
};

static size_t custom_payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct custom_payload_ctx *upload_ctx = (struct custom_payload_ctx *)userp;
    char *buf = (char *)ptr;
    size_t buffer_size;
    size_t total_read = 0;

    if (size == 0 || nmemb > (size_t)-1 / size) {
        return 0;
    }
    buffer_size = size * nmemb;

    /* Send header first */
    if (upload_ctx->header && upload_ctx->header[upload_ctx->header_pos] != '\0') {
        size_t header_len = strlen(upload_ctx->header + upload_ctx->header_pos);
        size_t to_copy = (header_len < buffer_size) ? header_len : buffer_size;

        memcpy(buf, upload_ctx->header + upload_ctx->header_pos, to_copy);
        upload_ctx->header_pos += to_copy;
        buf += to_copy;
        buffer_size -= to_copy;
        total_read += to_copy;
    }

    /* Then send body from file */
    if (buffer_size > 0 && upload_ctx->body_fp) {
        size_t read_bytes = fread(buf, 1, buffer_size, upload_ctx->body_fp);
        total_read += read_bytes;
    }

    return total_read;
}
#endif

/* Return codes (from SMTP server) */
#define VALIDBANNER     "220"
#define VALIDMAIL       "250"
#define VALIDDATA       "354"

/* SMTP curl timeouts */
#define CONNECT_TIMEOUT 30
#define TRANSFER_TIMEOUT 120
#define HOSTNAME_MAX    253

/* Default values used to connect */
#define SMTP_DEFAULT_PORT   "25"
#define HELOMSG             "Helo notify.ossec.net\r\n"
#define MAILFROM            "Mail From: <%s>\r\n"
#define RCPTTO              "Rcpt To: <%s>\r\n"
#define DATAMSG             "DATA\r\n"
#define FROM                "From: OSSEC HIDS <%s>\r\n"
#define REPLYTO             "Reply-To: OSSEC HIDS <%s>\r\n"
#define TO                  "To: <%s>\r\n"
#define CC                  "Cc: <%s>\r\n"
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

/* Allow only hostname-safe chars (alphanumeric, hyphen, dot) or IPv6 literals.
 * Reject empty, overlength, or strings with malicious characters. */
static int is_valid_smtp_host(const char *host)
{
    size_t n = 0;
    if (!host || !host[0]) return 0;
    for (; host[n]; n++) {
        if (n > 255) return 0;
        /* Allow alphanumeric, hyphen, dot, colon (IPv6), and brackets (IPv6 literal) */
        if (!isalnum((unsigned char)host[n]) && host[n] != '-' && host[n] != '.' &&
            host[n] != ':' && host[n] != '[' && host[n] != ']') {
            return 0;
        }
    }
    return (n > 0 && n <= HOSTNAME_MAX);
}

int OS_SendCustomEmail2(char **to, char *subject, char *fname, monitor_config *mail)
{
    char *smtpserver = mail->smtpserver;
    char *from = mail->emailfrom;
    char *idsname = mail->emailidsname;
#ifdef USE_SMTP_CURL
    CURL *curl;
    CURLcode res = CURLE_OK;
    struct curl_slist *recipients = NULL;
    struct curl_slist *host = NULL;
    struct custom_payload_ctx upload_ctx;
    char mail_url[256];
    char *header_buf = NULL;
    size_t header_len = 0;
    size_t header_pos = 0;
    char curl_errbuf[CURL_ERROR_SIZE];
#endif
    FILE *sendmail = NULL;
    int smtp_socket = -1, i = 0;
    char *msg;
    char snd_msg[128];
    char buffer[2049];
    char sanitized_from[384];
    char sanitized_idsname[384];
    char sanitized_subject[512];
    time_t tm;
    struct tm *p;

    if (!smtpserver || !from) {
        return (OS_INVALID);
    }

    /* Sanitize inputs to prevent header injection */
    sanitize_header_value(from, sanitized_from, sizeof(sanitized_from));
    sanitize_header_value(idsname ? idsname : "", sanitized_idsname, sizeof(sanitized_idsname));
    sanitize_header_value(subject ? subject : "", sanitized_subject, sizeof(sanitized_subject));

    buffer[2048] = '\0';

#ifdef USE_SMTP_CURL
    if (smtpserver[0] == '/') {
        /* Local sendmail pipe not implemented via curl path; fall back to legacy if needed or just popen */
        goto legacy_path;
    }

    curl = curl_easy_init();
    if (!curl) {
        return (OS_INVALID);
    }

    upload_ctx.body_fp = fopen(fname, "r");
    if (!upload_ctx.body_fp) {
        merror("%s: ERROR: Cannot open %s: %s", ARGV0, fname, strerror(errno));
        curl_easy_cleanup(curl);
        return (OS_INVALID);
    }

    /* Build header */
    tm = time(NULL);
    p = localtime(&tm);
    char date_buf[128];
#ifdef SOLARIS
    strftime(date_buf, 127, "Date: %a, %d %b %Y %T -0000\r\n", p);
#else
    strftime(date_buf, 127, "Date: %a, %d %b %Y %T %z\r\n", p);
#endif

    header_len = 4096; /* dynamic enough for many recipients */
    os_calloc(header_len, sizeof(char), header_buf);
    
    int n = snprintf(header_buf + header_pos, header_len - header_pos, "To: ");
    if (n > 0 && header_pos + n < header_len) header_pos += n;

    i = 0;
    while (to[i]) {
        char sanitized_to[384];
        sanitize_header_value(to[i], sanitized_to, sizeof(sanitized_to));
        n = snprintf(header_buf + header_pos, header_len - header_pos,
                     "<%s>%s", sanitized_to, to[i+1] ? ", " : "\r\n");
        if (n < 0 || header_pos + (size_t)n >= header_len - 1024) {
            merror("%s: ERROR: Header buffer too small to hold all recipients. Truncating visible 'To:' list.", ARGV0);
            if (header_pos < header_len - 3) {
                snprintf(header_buf + header_pos, header_len - header_pos, "\r\n");
                header_pos += 2;
            }
            break;
        }
        header_pos += n;
        i++;
    }

    n = snprintf(header_buf + header_pos, header_len - header_pos,
                 "From: OSSEC HIDS <%s>\r\n"
                 "Subject: %s\r\n"
                 "%s"
                 "X-IDS-OSSEC: %s\r\n"
                 "\r\n",
                 sanitized_from, sanitized_subject, date_buf, sanitized_idsname);
    
    if (n < 0 || header_pos + (size_t)n >= header_len) {
        merror("%s: ERROR: Header buffer too small for combined headers (truncation).", ARGV0);
        res = CURLE_OUT_OF_MEMORY;
        goto cleanup_curl;
    }
    header_pos += n;

    upload_ctx.header = header_buf;
    upload_ctx.header_pos = 0;

    /* Build URL */
    int port = mail->smtp_port > 0 ? mail->smtp_port : (mail->securesmtp ? 465 : 25);
    int n2;

    if (!is_valid_smtp_host(smtpserver)) {
        merror("%s: ERROR: Invalid SMTP server '%s' (contains invalid characters).", ARGV0, smtpserver);
        return (0);
    }

    /* Bracket IPv6 literals in the URL if not already bracketed */
    if (strchr(smtpserver, ':') && smtpserver[0] != '[') {
        n2 = snprintf(mail_url, sizeof(mail_url), "smtp%s://[%s]:%d",
                 mail->securesmtp ? "s" : "", smtpserver, port);
    } else {
        n2 = snprintf(mail_url, sizeof(mail_url), "smtp%s://%s:%d",
                 mail->securesmtp ? "s" : "", smtpserver, port);
    }

    if (n2 < 0 || (size_t)n2 >= sizeof(mail_url)) {
        merror("%s: ERROR: SMTP server or URL too long (truncation).", ARGV0);
        return (0);
    }

    curl_easy_setopt(curl, CURLOPT_URL, mail_url);

    /* Timeouts and signal handling */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)TRANSFER_TIMEOUT);
    
    /* Error buffer for detailed failure logging */
    memset(curl_errbuf, 0, sizeof(curl_errbuf));
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);

    /* Explicit TLS verification so behavior is not dependent on libcurl defaults */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    if (mail->authsmtp && mail->smtp_user && mail->smtp_pass) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, mail->smtp_user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, mail->smtp_pass);
        /* Require TLS when using AUTH so credentials are not sent in plaintext */
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    }

    if (mail->securesmtp) {
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    }

    /* DNS resolution pre-resolved (prior to chroot) */
    if (mail->smtpserver_resolved) {
        char resolve_buf[384];
        char *resolved_ip = mail->smtpserver_resolved;
        int n_res;
        
        /* Bracket IPv6 addresses */
        if (strchr(resolved_ip, ':')) {
            n_res = snprintf(resolve_buf, sizeof(resolve_buf), "%s:%d:[%s]",
                     smtpserver, port, resolved_ip);
        } else {
            n_res = snprintf(resolve_buf, sizeof(resolve_buf), "%s:%d:%s",
                     smtpserver, port, resolved_ip);
        }
        if (n_res < 0 || (size_t)n_res >= sizeof(resolve_buf)) {
            merror("%s: ERROR: SMTP server or resolved IP too long for CURLOPT_RESOLVE (truncation).", ARGV0);
            res = CURLE_URL_MALFORMAT;
            goto cleanup_curl;
        }
        host = curl_slist_append(NULL, resolve_buf);
        if (!host) {
            merror("%s: ERROR: Memory error building CURLOPT_RESOLVE list.", ARGV0);
            res = CURLE_OUT_OF_MEMORY;
            goto cleanup_curl;
        }
        curl_easy_setopt(curl, CURLOPT_RESOLVE, host);
    }

    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, sanitized_from);
    i = 0;
    while (to[i]) {
        if (strchr(to[i], '\r') || strchr(to[i], '\n')) {
            merror("%s: Skipping recipient with invalid CR/LF (SMTP injection attempt or misconfiguration).", ARGV0);
            i++;
            continue;
        }
        struct curl_slist *tmp_recipients = curl_slist_append(recipients, to[i]);
        if (!tmp_recipients) {
            merror("%s: ERROR: Memory error building recipient list.", ARGV0);
            res = CURLE_OUT_OF_MEMORY;
            goto cleanup_curl;
        }
        recipients = tmp_recipients;
        i++;
    }
    
    if (!recipients) {
        merror("%s: ERROR: No valid recipients found after filtering. Aborting report send.", ARGV0);
        res = CURLE_FAILED_INIT;
        goto cleanup_curl;
    }
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, custom_payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        merror("%s: ERROR: SMTP perform failed: %s", ARGV0, curl_easy_strerror(res));
        if (curl_errbuf[0] != '\0') {
            merror("%s: curl error detail: %s", ARGV0, curl_errbuf);
        }
    }

cleanup_curl:
    curl_slist_free_all(recipients);
    if (host) {
        curl_slist_free_all(host);
    }
    curl_easy_cleanup(curl);
    fclose(upload_ctx.body_fp);
    free(header_buf);

    return (res == CURLE_OK ? 0 : OS_INVALID);

legacy_path:
    ; /* A label can only be part of a statement */
#endif

    if (smtpserver[0] == '/') {
        sendmail = popen(smtpserver, "w");
        if (!sendmail) {
            return (OS_INVALID);
        }
    } else {
        /* Connect to the SMTP server */
        smtp_socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, smtpserver);
        if (smtp_socket < 0) {
            return (smtp_socket);
        }

        /* Receive the banner */
        msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(smtp_socket);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
        free(msg);

        /* Send HELO message */
        OS_SendTCP(smtp_socket, HELOMSG);
        msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                /* In some cases (with virus scans in the middle)
                 * we may get two banners. Check for that in here.
                 */
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);

                    /* Try again */
                    msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(smtp_socket);
                        return (OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(smtp_socket);
                    return (OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(smtp_socket);
                return (OS_INVALID);
            }
        }

        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", HELOMSG, msg);
        free(msg);

        /* Build "Mail from" msg */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, MAILFROM, sanitized_from);
        OS_SendTCP(smtp_socket, snd_msg);
        msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            merror(FROM_ERROR);
            if (msg) {
                free(msg);
            }
            close(smtp_socket);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

        /* Build "RCPT TO" msg */
        i = 0;
        while (to[i]) {
            char sanitized_to[384];
            sanitize_header_value(to[i], sanitized_to, sizeof(sanitized_to));
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, RCPTTO, sanitized_to);
            OS_SendTCP(smtp_socket, snd_msg);
            msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(TO_ERROR, to[i]);
                if (msg) {
                    free(msg);
                }
                close(smtp_socket);
                return (OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);

            i++;
        }

        /* Send the "DATA" msg */
        OS_SendTCP(smtp_socket, DATAMSG);
        msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
            merror(DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(smtp_socket);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
        free(msg);
    }

    /* Build "From" and "To" in the e-mail header */
    memset(snd_msg, '\0', 128);
    {
        char sanitized_to[384];
        sanitize_header_value(to[0], sanitized_to, sizeof(sanitized_to));
        snprintf(snd_msg, 127, TO, sanitized_to);
    }

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(smtp_socket, snd_msg);
    }

    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, FROM, sanitized_from);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(smtp_socket, snd_msg);
    }

    /* Add CCs */
    if (to[1]) {
        i = 1;
        while (to[i] != NULL) {
            char sanitized_to[384];
            sanitize_header_value(to[i], sanitized_to, sizeof(sanitized_to));
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, TO, sanitized_to);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
                OS_SendTCP(smtp_socket, snd_msg);
            }

            i++;
        }
    }

    /* Send date */
    memset(snd_msg, '\0', 128);
    tm = time(NULL);
    p = localtime(&tm);

    /* Solaris doesn't have the "%z", so we set the timezone to 0 */
#ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n", p);
#else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n", p);
#endif

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
        OS_SendTCP(smtp_socket, snd_msg);
    }

    if (idsname) {
        /* Send server name header */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, XHEADER, sanitized_idsname);

        if (sendmail) {
            fprintf(sendmail, "%s", snd_msg);
        } else {
            OS_SendTCP(smtp_socket, snd_msg);
        }
    }

    /* Send subject */
    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, SUBJECT, sanitized_subject);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
        fprintf(sendmail, ENDHEADER);
    } else {
        OS_SendTCP(smtp_socket, snd_msg);
        OS_SendTCP(smtp_socket, ENDHEADER);
    }


    /* Send body */
    FILE *fp;
    fp = fopen(fname, "r");
    if(!fp) {
        merror("%s: ERROR: Cannot open %s: %s", __local_name, fname, strerror(errno));
        if(smtp_socket >= 0) {
            close(smtp_socket);
        }
        if(sendmail) {
            pclose(sendmail);
        }
        return(1);
    }


    while (fgets(buffer, 2048, fp) != NULL) {
        if (sendmail) {
            fprintf(sendmail, "%s", buffer);
        } else {
            OS_SendTCP(smtp_socket, buffer);
        }
    }
    fclose(fp);

    if (sendmail) {
        if (pclose(sendmail) == -1) {
            merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
        }
    } else {
        /* Send end of data \r\n.\r\n */
        OS_SendTCP(smtp_socket, ENDDATA);
        msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);

        /* Check msg, since it may be null */
        if (msg) {
            free(msg);
        }

        /* Quit and close socket */
        OS_SendTCP(smtp_socket, QUITMSG);
        msg = OS_RecvTCP(smtp_socket, OS_SIZE_1024);

        if (msg) {
            free(msg);
        }

        close(smtp_socket);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}

