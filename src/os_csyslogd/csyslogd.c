/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "csyslogd.h"
#include "json-queue.h"

/* Global variables */
char __shost[512];
char __shost_long[512];

typedef struct alert_source_t {
    int alert_log;
    int alert_json;
} alert_source_t;

/* Drain this many JSON objects before reading alerts.log so a JSON flood
 * cannot starve default/CEF/Splunk destinations, and log waits cannot
 * leave JSON one-alert-per-timeout. */
#define JSON_DRAIN_MAX 64

static alert_source_t get_alert_sources(SyslogConfig **syslog_config)
{
    alert_source_t sources = {0, 0};
    int i;

    if (!syslog_config) {
        return sources;
    }

    for (i = 0; syslog_config[i]; i++) {
        if (syslog_config[i]->format == JSON_CSYSLOG) {
            sources.alert_json = 1;
        } else {
            sources.alert_log = 1;
        }
    }

    return sources;
}

static void send_json_alert(cJSON *json_data, SyslogConfig **syslog_config)
{
    int s = 0;

    if (!json_data || !syslog_config) {
        return;
    }

    while (syslog_config[s]) {
        if (syslog_config[s]->format == JSON_CSYSLOG) {
            OS_Alert_SendSyslog_JSON(json_data, syslog_config[s]);
        }
        s++;
    }
}

/* Monitor the alerts and send them via syslog
 * Only return in case of error
 */
void OS_CSyslogD(SyslogConfig **syslog_config)
{
    int s = 0;
    time_t tm;
    struct tm tm_buf;
    struct tm *p;
    int tries = 0;
    int drained;
    unsigned int log_timeout;
    alert_source_t sources;
    file_queue *fileq = NULL;
    file_queue jfileq;
    alert_data *al_data = NULL;
    cJSON *json_data = NULL;

    if (!syslog_config) {
        merror("%s: ERROR: No syslog_output configurations available. Exiting.", ARGV0);
        exit(1);
    }

    sources = get_alert_sources(syslog_config);

    if (sources.alert_log) {
        tm = time(NULL);
        p = localtime_r(&tm, &tm_buf);
        if (!p) {
            merror("%s: ERROR: localtime_r failed while opening alerts.log queue.", ARGV0);
            exit(1);
        }

        os_calloc(1, sizeof(file_queue), fileq);
        while ((Init_FileQueue(fileq, p, 0)) < 0) {
            tries++;
            if (tries > OS_CSYSLOGD_MAX_TRIES) {
                merror("%s: ERROR: Could not open alerts.log queue after %d tries, exiting!",
                       ARGV0, tries);
                exit(1);
            }
            sleep(1);
        }
        debug1("%s: INFO: File queue connected.", ARGV0);
    }

    if (sources.alert_json) {
        jqueue_init(&jfileq);
        tries = 0;
        while (jqueue_open(&jfileq, 1) < 0) {
            tries++;
            if (tries > OS_CSYSLOGD_MAX_TRIES) {
                merror("%s: ERROR: Could not open alerts.json after %d tries; "
                       "JSON syslog_output will retry (enable jsonout_output / wait for first alert).",
                       ARGV0, tries);
                break;
            }
            sleep(1);
        }
        if (jfileq.fp) {
            debug1("%s: INFO: JSON file queue connected.", ARGV0);
        }
    }

    if (!sources.alert_log && !sources.alert_json) {
        merror("%s: ERROR: No syslog_output configurations available. Exiting.", ARGV0);
        exit(1);
    }

    /* UDP sockets were opened in main() before chroot (#1744). */

    /* Infinite loop reading the alerts and inserting them */
    while (1) {
        al_data = NULL;
        drained = 0;

        if (sources.alert_json) {
            while (drained < JSON_DRAIN_MAX &&
                   (json_data = jqueue_next(&jfileq)) != NULL) {
                send_json_alert(json_data, syslog_config);
                cJSON_Delete(json_data);
                drained++;
            }
        }

        if (sources.alert_log && drained < JSON_DRAIN_MAX) {
            tm = time(NULL);
            p = localtime_r(&tm, &tm_buf);
            if (p && fileq) {
                /* Mixed JSON+log: one FileMon wait (5s) instead of five, so
                 * JSON catch-up is not delayed up to 25s. Skip the log wait
                 * while a JSON batch is still draining. */
                log_timeout = sources.alert_json ? 1 : 5;
                al_data = Read_FileMon(fileq, p, log_timeout);
            }
        }

        if (al_data) {
            s = 0;
            while (syslog_config[s]) {
                if (syslog_config[s]->format != JSON_CSYSLOG) {
                    OS_Alert_SendSyslog(al_data, syslog_config[s]);
                }
                s++;
            }
            FreeAlertData(al_data);
        }

        /* JSON-only (or mixed with no log event this pass) needs a wait
         * when FileMon is not sleeping for us. */
        if (!sources.alert_log && drained == 0) {
            sleep(1);
        }
    }
}

/* Format Field for output */
int field_add_string(char *dest, size_t size, const char *format, const char *value )
{
    char buffer[OS_CSYSLOG_MAX];
    int len = 0;
    size_t dest_len;
    size_t dest_sz;
    size_t lim;

    if (!dest || size == 0) {
        return -1;
    }

    dest_len = strlen(dest);
    if (dest_len >= size) {
        return -1;
    }

    dest_sz = size - dest_len;
    if (dest_sz <= 1) {
        return -1;
    }

    if (value != NULL &&
            (
                ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
                ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
                ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
            )
       ) {
        lim = sizeof(buffer);
        if (lim > dest_sz) {
            lim = dest_sz;
        }
        len = snprintf(buffer, lim, format, value);
        strncat(dest, buffer, dest_sz - 1);
    }

    return len;
}

/* Add a field, but truncate if too long */
int field_add_truncated(char *dest, size_t size, const char *format, const char *value, int fmt_size )
{
    char buffer[OS_CSYSLOG_MAX];
    size_t dest_len;
    size_t available_sz;
    size_t total_sz;
    size_t field_sz;
    size_t lim;
    int len = 0;
    char trailer[] = "...";
    char *truncated = NULL;

    if (!dest || !value || size == 0) {
        return -1;
    }

    dest_len = strlen(dest);
    if (dest_len >= size) {
        return -1;
    }

    available_sz = size - dest_len;
    if (available_sz <= 1) {
        return -1;
    }

    total_sz = strlen(value);
    {
        size_t fmt_len = strlen(format);

        if (fmt_size < 0 || (size_t)fmt_size > fmt_len) {
            return -1;
        }
        total_sz += fmt_len - (size_t)fmt_size;
        if (available_sz <= fmt_len - (size_t)fmt_size) {
            return -1;
        }
        field_sz = available_sz - fmt_len + (size_t)fmt_size;
    }

    if (
        ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
        ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
        ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
       ) {

        if ( (truncated = (char *) malloc(field_sz + 1)) != NULL ) {
            if ( total_sz > available_sz ) {
                size_t trailer_len = strlen(trailer);

                /* field_sz is size_t; subtracting trailer_len without a
                 * guard underflows and lets os_substr overrun truncated. */
                if (field_sz <= trailer_len) {
                    free(truncated);
                    return -1;
                }
                os_substr(truncated, value, 0, field_sz - trailer_len);
                strcat(truncated, trailer);
            } else {
                strncpy(truncated, value, field_sz);
                truncated[field_sz] = '\0';
            }

            lim = sizeof(buffer);
            if (lim > available_sz) {
                lim = available_sz;
            }
            len = snprintf(buffer, lim, format, truncated);
            strncat(dest, buffer, available_sz - 1);
        } else {
            /* Memory Error */
            len = -3;
        }
    }
    /* Free the temporary pointer */
    free(truncated);

    return len;
}

/* Handle integers in the second position */
int field_add_int(char *dest, size_t size, const char *format, const int value )
{
    char buffer[255];
    int len = 0;
    int dest_sz = size - strlen(dest);

    /* Not enough room in the buffer? */
    if (dest_sz <= 0 ) {
        return -1;
    }

    if ( value > 0 ) {
        len = snprintf(buffer, sizeof(buffer), format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}

