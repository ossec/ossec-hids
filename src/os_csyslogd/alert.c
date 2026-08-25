/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdbool.h>

#include "csyslogd.h"
#include "cJSON.h"
#include "config/config.h"
#include "os_net/os_net.h"


/* Escape CEF messages according to the standards */
char *cefescape(const char *msg, const bool header)
{
    static char *buffer = NULL;
    const char *ptr;
    char *buffptr;
    size_t size;
    int needs_escape = 0;

    /* Recycle the buffer */
    if (buffer) {
        os_free(buffer);
        buffer = NULL;
    }

    /* Cleanup call */
    if (NULL == msg) {
        return NULL;
    }

    if (header && strchr(msg, '|')) {
        needs_escape = 1;
    }
    if (!header && strchr(msg, '=')) {
        needs_escape = 1;
    }
    if (strchr(msg, '\\') || strchr(msg, '\r') || strchr(msg, '\n')) {
        needs_escape = 1;
    }
    if (!needs_escape) {
        return (char *)msg;
    }

    /* Calculate the size of the escaped message
     *
     * In the header we replace \r and \n with a
     * space, so there's no change in size.
     */
    ptr = msg;
    size = 1;
    while (*ptr) {
        if (('\\' == *ptr) ||
            (header && ('|' == *ptr)) ||
            (!header && (
                ('=' == *ptr) ||
                ('\r' == *ptr) ||
                ('\n' == *ptr)
            )))
        {
            size += 2;
        } else {
            size += 1;
        }
        ptr++;
    }

    /* Allocate the new buffer and start escaping */
    buffer = (char*) malloc(size);
    buffer[size-1] = '\0';
    ptr = msg;
    buffptr = buffer;
    while (*ptr) {
        if ('\\' == *ptr) {
            *buffptr = '\\';
            *(buffptr + 1) = '\\';
            buffptr += 2;
        } else if ('\r' == *ptr) {
            *buffptr = header ? ' ' : '\\';
            buffptr++;
            if (!header) {
                *buffptr = 'r';
                buffptr++;
            }
        } else if ('\n' == *ptr) {
            *buffptr = header ? ' ' : '\\';
            buffptr++;
            if (!header) {
                *buffptr = 'n';
                buffptr++;
            }
        } else if (header && ('|' == *ptr)) {
            *buffptr = '\\';
            *(buffptr + 1) = '|';
            buffptr += 2;
        } else if (!header && ('=' == *ptr)) {
            *buffptr = '\\';
            *(buffptr + 1) = '=';
            buffptr += 2;
        } else {
            *buffptr = *ptr;
            buffptr++;
        }
        ptr++;
    }

    return buffer;
}

/* Send an alert via syslog
 * Returns 1 on success or 0 on error
 */
int OS_Alert_SendSyslog(alert_data *al_data, SyslogConfig *syslog_config)
{
    char *logmsg = NULL;
    int logmsg_allocated = 0;
    int result = 0;
    char *tstamp;
    char *hostname;
    char syslog_msg[OS_CSYSLOG_MAX];

    /* Socket may be -1 after a prior send failure; csyslog_send reconnects. */

    if (!al_data || !syslog_config) {
        return (0);
    }

    /* JSON format is forwarded from alerts.json via OS_Alert_SendSyslog_JSON. */
    if (syslog_config->format == JSON_CSYSLOG) {
        return (0);
    }

    /* Clear the memory before insert */
    memset(syslog_msg, '\0', OS_CSYSLOG_MAX);

    /* Look if location is set */
    if (syslog_config->location) {
        if (!OSMatch_Execute(al_data->location,
                             strlen(al_data->location),
                             syslog_config->location)) {
            return (0);
        }
    }

    /* Look for the level */
    if (syslog_config->level) {
        if (al_data->level < syslog_config->level) {
            return (0);
        }
    }

    /* Look for rule id */
    if (syslog_config->rule_id) {
        int id_i = 0;
        while (syslog_config->rule_id[id_i] != 0) {
            if (syslog_config->rule_id[id_i] == al_data->rule) {
                break;
            }
            id_i++;
        }

        /* If we found, id is going to be a valid rule */
        if (!syslog_config->rule_id[id_i]) {
            return (0);
        }
    }

    /* Look for the group */
    if (syslog_config->group) {
        if (!OSMatch_Execute(al_data->group,
                             strlen(al_data->group),
                             syslog_config->group)) {
            return (0);
        }
    }

    /* Fix the timestamp to be syslog compatible
     * We have 2008 Jul 10 10:11:23
     * Should be: Jul 10 10:11:23
     */
    tstamp = al_data->date;
    if (strlen(al_data->date) > 14) {
        tstamp += 5;

        /* Fix first digit if the day is < 10 */
        if (tstamp[4] == '0') {
            tstamp[4] = ' ';
        }
    }

    if (syslog_config->use_fqdn) {
        hostname = __shost_long;
    } else {
        hostname = __shost;
    }

    /* Walk the log lines */
    if (al_data->log && al_data->log[0]) {
        if (NULL == al_data->log[1]) {
            logmsg = al_data->log[0];
        } else {
            short int i = 0;
            logmsg_allocated = 1;
            while (NULL != al_data->log[i]) {
                logmsg = os_LoadString(logmsg, al_data->log[i]);
                i++;
                if (NULL != al_data->log[i]) {
                    logmsg = os_LoadString(logmsg, "\n");
                }
                /* Save on memory and processing since it's going to get truncated anyway */
                if (logmsg && OS_CSYSLOG_MAX <= strlen(logmsg)) {
                    break;
                }
            }
        }
    }

    /* Insert data */
    if (syslog_config->format == DEFAULT_CSYSLOG) {
        /* Build syslog message */
        snprintf(syslog_msg, OS_CSYSLOG_MAX,
                 "<%u>%s %s ossec: Alert Level: %u; Rule: %u - %s; Location: %s;",
                 syslog_config->priority, tstamp, hostname,
                 al_data->level,
                 al_data->rule, al_data->comment,
                 al_data->location
                );
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " classification: %s;", al_data->group);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " srcip: %s;", al_data->srcip);
#ifdef LIBGEOIP_ENABLED
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " srccity: %s;", al_data->srcgeoip);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " dstcity: %s;", al_data->dstgeoip);
#endif
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " dstip: %s;", al_data->dstip);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " user: %s;", al_data->user);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Previous MD5: %s;", al_data->old_md5);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Current MD5: %s;", al_data->new_md5);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Previous SHA1: %s;", al_data->old_sha1);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Current SHA1: %s;", al_data->new_sha1);
        /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Size changed: from %s;", al_data->file_size);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " User ownership: was %s;", al_data->owner_chg);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Group ownership: was %s;", al_data->group_chg);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " Permissions changed: from %s;", al_data->perm_chg);
        /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
        field_add_truncated(syslog_msg, OS_CSYSLOG_MAX, " %s", logmsg, 2);
    } else if (syslog_config->format == CEF_CSYSLOG) {
        /* Start with headers */
        snprintf(syslog_msg, OS_CSYSLOG_MAX,
                 "<%u>%s CEF:0|%s|%s|%s|%u|%s|%u|",
                 syslog_config->priority,
                 tstamp,
                 __author,
                 __ossec_name,
                 __ossec_version,
                 al_data->rule,
                 cefescape(al_data->comment, true),
                 (al_data->level > 10) ? 10 : al_data->level);
        /* Add extensions */
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, "dvc=%s", cefescape(hostname, false));
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " cs1Label=Location cs1=%s", cefescape(al_data->location, false));
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " classification=%s", cefescape(al_data->group, false));
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " src=%s", al_data->srcip);
        field_add_int(syslog_msg, OS_CSYSLOG_MAX, " dpt=%d", al_data->dstport);
        field_add_int(syslog_msg, OS_CSYSLOG_MAX, " spt=%d", al_data->srcport);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " fname=%s", cefescape(al_data->filename, false));
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " dhost=%s", al_data->dstip);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " shost=%s", al_data->srcip);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " suser=%s", cefescape(al_data->user, false));
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " dst=%s", cefescape(al_data->dstip, false));
#ifdef LIBGEOIP_ENABLED
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " cs4Label=SrcCity cs4=%s", cefescape(al_data->srcgeoip, false));
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " cs5Label=DstCity cs5=%s", cefescape(al_data->dstgeoip, false));
#endif
        if (al_data->new_md5 && al_data->new_sha1) {
            field_add_string(syslog_msg, OS_CSYSLOG_MAX, " cs2Label=OldMD5 cs2=%s", al_data->old_md5);
            field_add_string(syslog_msg, OS_CSYSLOG_MAX, " cs3Label=NewMD5 cs3=%s", al_data->new_md5);
            field_add_string(syslog_msg, OS_CSYSLOG_MAX, " oldFileHash=%s", al_data->old_sha1);
            field_add_string(syslog_msg, OS_CSYSLOG_MAX, " fhash=%s", al_data->new_sha1);
            field_add_string(syslog_msg, OS_CSYSLOG_MAX, " fileHash=%s", al_data->new_sha1);
        }
        field_add_truncated(syslog_msg, OS_CSYSLOG_MAX, " msg=%s", cefescape(logmsg, false), 2);
        cefescape(NULL,0);  /* Clean up the escaping buffer */
    } else if (syslog_config->format == SPLUNK_CSYSLOG) {
        /* Build a Splunk Style Key/Value string for logging */
        snprintf(syslog_msg, OS_CSYSLOG_MAX,
                 "<%u>%s %s ossec: crit=%u id=%u description=\"%s\" component=\"%s\",",

                 /* syslog header */
                 syslog_config->priority, tstamp, hostname,

                 /* OSSEC metadata */
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location
                );
        /* Event specifics */
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " classification=\"%s\",", al_data->group);

        if (field_add_string(syslog_msg, OS_CSYSLOG_MAX, " src_ip=\"%s\",", al_data->srcip) > 0) {
            field_add_int(syslog_msg, OS_CSYSLOG_MAX, " src_port=%d,", al_data->srcport);
        }

#ifdef LIBGEOIP_ENABLED
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " src_city=\"%s\",", al_data->srcgeoip);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " dst_city=\"%s\",", al_data->dstgeoip);
#endif

        if (field_add_string(syslog_msg, OS_CSYSLOG_MAX, " dst_ip=\"%s\",", al_data->dstip) > 0) {
            field_add_int(syslog_msg, OS_CSYSLOG_MAX, " dst_port=%d,", al_data->dstport);
        }

        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " file=\"%s\",", al_data->filename);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " acct=\"%s\",", al_data->user);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " md5_old=\"%s\",", al_data->old_md5);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " md5_new=\"%s\",", al_data->new_md5);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " sha1_old=\"%s\",", al_data->old_sha1);
        field_add_string(syslog_msg, OS_CSYSLOG_MAX, " sha1_new=\"%s\",", al_data->new_sha1);
        /* Message */
        field_add_truncated(syslog_msg, OS_CSYSLOG_MAX, " message=\"%s\"", logmsg, 2);
    }

    if (csyslog_send(syslog_config, syslog_msg, strlen(syslog_msg)) == 0) {
        result = 1;
    }

    if (logmsg_allocated) {
        free(logmsg);
    }
    return (result);
}

static int json_match_string(OSMatch *matcher, cJSON *item)
{
    if (!matcher || !cJSON_IsString(item) || !item->valuestring) {
        return 0;
    }
    return OSMatch_Execute(item->valuestring, strlen(item->valuestring), matcher);
}

static void json_syslog_stub(char *dest, size_t dest_sz, unsigned int priority,
                             const char *tstamp, const char *hostname,
                             cJSON *json_data, const char *reason)
{
    cJSON *stub;
    cJSON *rule;
    cJSON *item;
    char *payload;

    stub = cJSON_CreateObject();
    if (!stub) {
        snprintf(dest, dest_sz, "<%u>%s %s ossec: {\"truncated\":true}",
                 priority, tstamp, hostname);
        return;
    }

    item = cJSON_GetObjectItem(json_data, "agent_name");
    if (cJSON_IsString(item) && item->valuestring) {
        cJSON_AddStringToObject(stub, "agent_name", item->valuestring);
    }
    rule = cJSON_GetObjectItem(json_data, "rule");
    if (rule) {
        cJSON *rr = cJSON_CreateObject();
        item = cJSON_GetObjectItem(rule, "sidid");
        if (cJSON_IsNumber(item)) {
            cJSON_AddNumberToObject(rr, "sidid", item->valueint);
        }
        item = cJSON_GetObjectItem(rule, "level");
        if (cJSON_IsNumber(item)) {
            cJSON_AddNumberToObject(rr, "level", item->valueint);
        }
        cJSON_AddItemToObject(stub, "rule", rr);
    }
    cJSON_AddTrueToObject(stub, "truncated");
    if (reason) {
        cJSON_AddStringToObject(stub, "reason", reason);
    }

    payload = cJSON_PrintUnformatted(stub);
    cJSON_Delete(stub);
    if (payload) {
        snprintf(dest, dest_sz, "<%u>%s %s ossec: %s",
                 priority, tstamp, hostname, payload);
        free(payload);
    } else {
        snprintf(dest, dest_sz, "<%u>%s %s ossec: {\"truncated\":true}",
                 priority, tstamp, hostname);
    }
}

int OS_Alert_SendSyslog_JSON(cJSON *json_data, SyslogConfig *syslog_config)
{
    cJSON *rule;
    cJSON *item;
    cJSON *groups;
    char *json_string = NULL;
    char *hostname;
    char tstamp[32];
    char syslog_msg[OS_CSYSLOG_MAX];
    time_t now;
    struct tm tm_buf;
    struct tm *tm_p;
    int n;
    int result = 0;

    if (!json_data || !syslog_config) {
        return (0);
    }

    rule = cJSON_GetObjectItem(json_data, "rule");
    if (!rule) {
        debug2("%s: DEBUG: JSON alert missing rule field.", ARGV0);
        return (0);
    }

    if (syslog_config->location) {
        if (!json_match_string(syslog_config->location,
                               cJSON_GetObjectItem(json_data, "location")) &&
            !json_match_string(syslog_config->location,
                               cJSON_GetObjectItem(json_data, "logfile"))) {
            return (0);
        }
    }

    if (syslog_config->level) {
        item = cJSON_GetObjectItem(rule, "level");
        if (!cJSON_IsNumber(item) || item->valueint < (int)syslog_config->level) {
            return (0);
        }
    }

    if (syslog_config->rule_id) {
        int id_i = 0;
        int sid = 0;

        item = cJSON_GetObjectItem(rule, "sidid");
        if (!cJSON_IsNumber(item)) {
            return (0);
        }
        sid = item->valueint;
        while (syslog_config->rule_id[id_i] != 0) {
            if ((int)syslog_config->rule_id[id_i] == sid) {
                break;
            }
            id_i++;
        }
        if (!syslog_config->rule_id[id_i]) {
            return (0);
        }
    }

    if (syslog_config->group) {
        int found = 0;

        item = cJSON_GetObjectItem(rule, "group");
        if (json_match_string(syslog_config->group, item)) {
            found = 1;
        } else {
            groups = cJSON_GetObjectItem(rule, "groups");
            if (cJSON_IsArray(groups)) {
                cJSON_ArrayForEach(item, groups) {
                    if (json_match_string(syslog_config->group, item)) {
                        found = 1;
                        break;
                    }
                }
            }
        }
        if (!found) {
            return (0);
        }
    }

    now = time(NULL);
    item = cJSON_GetObjectItem(json_data, "TimeStamp");
    if (cJSON_IsNumber(item) && item->valuedouble > 0) {
        now = (time_t)(item->valuedouble / 1000.0);
    }

    tm_p = localtime_r(&now, &tm_buf);
    if (!tm_p) {
        snprintf(tstamp, sizeof(tstamp), "Jan  1 00:00:00");
    } else {
        strftime(tstamp, sizeof(tstamp), "%b %d %T", tm_p);
        if (tstamp[4] == '0') {
            tstamp[4] = ' ';
        }
    }

    hostname = syslog_config->use_fqdn ? __shost_long : __shost;
    json_string = cJSON_PrintUnformatted(json_data);
    memset(syslog_msg, '\0', OS_CSYSLOG_MAX);

    if (json_string) {
        n = snprintf(syslog_msg, OS_CSYSLOG_MAX,
                     "<%u>%s %s ossec: %s",
                     syslog_config->priority, tstamp, hostname, json_string);
        if (n < 0) {
            merror("%s: WARN: syslog_output JSON alert encode failed; sending stub.",
                   ARGV0);
            json_syslog_stub(syslog_msg, OS_CSYSLOG_MAX, syslog_config->priority,
                             tstamp, hostname, json_data, "encode");
        } else if ((size_t)n >= OS_CSYSLOG_MAX) {
            merror("%s: WARN: syslog_output JSON alert truncated; sending compact stub.",
                   ARGV0);
            json_syslog_stub(syslog_msg, OS_CSYSLOG_MAX, syslog_config->priority,
                             tstamp, hostname, json_data, "size");
        }
        free(json_string);
    } else {
        snprintf(syslog_msg, OS_CSYSLOG_MAX,
                 "<%u>%s %s ossec: {\"error\":\"json_encode\"}",
                 syslog_config->priority, tstamp, hostname);
    }

    if (csyslog_send(syslog_config, syslog_msg, strlen(syslog_msg)) == 0) {
        result = 1;
    }
    return (result);
}


