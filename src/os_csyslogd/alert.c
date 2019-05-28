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

    /* Recycle the buffer */
    if (buffer) {
        os_free(buffer);
        buffer = NULL;
    }

    /* Test if the string needs escaping */
    if ((NULL == msg) ||                            /* Cleanup call or empty string */
        ((header && (NULL == strchr(msg, '|'))) &&  /* | in the header must be escaped */
        (!header && (NULL == strchr(msg, '='))) &&  /* = in the extension must be escaped */
        (NULL == strchr(msg, '\\')) &&              /* \ must be escaped */
        (NULL == strchr(msg, '\r')) &&              /* \r removed from header, escaped in extension */
        (NULL == strchr(msg, '\n')))) {             /* \n removed from header, escaped in extension */
        return buffer;
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
int OS_Alert_SendSyslog(alert_data *al_data, const SyslogConfig *syslog_config)
{
    char *logmsg = NULL;
    char *tstamp;
    char *hostname;
    char syslog_msg[OS_SIZE_2048];

    /* Invalid socket */
    if (syslog_config->socket < 0) {
        return (0);
    }

    /* Clear the memory before insert */
    memset(syslog_msg, '\0', OS_SIZE_2048);

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
            while (NULL != al_data->log[i]) {
                logmsg = os_LoadString(logmsg, al_data->log[i]);
                i++;
                if (NULL != al_data->log[i]) {
                    logmsg = os_LoadString(logmsg, "\n");
                }
                /* Save on memory and processing since it's going to get truncated anyway */
                if (OS_SIZE_2048 <= strlen(logmsg)) {
                    break;
                }
            }
        }
    }

    /* Insert data */
    if (syslog_config->format == DEFAULT_CSYSLOG) {
        /* Build syslog message */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s %s ossec: Alert Level: %u; Rule: %u - %s; Location: %s;",
                 syslog_config->priority, tstamp, hostname,
                 al_data->level,
                 al_data->rule, al_data->comment,
                 al_data->location
                );
        field_add_string(syslog_msg, OS_SIZE_2048, " classification: %s;", al_data->group);
        field_add_string(syslog_msg, OS_SIZE_2048, " srcip: %s;", al_data->srcip);
#ifdef LIBGEOIP_ENABLED
        field_add_string(syslog_msg, OS_SIZE_2048, " srccity: %s;", al_data->srcgeoip);
        field_add_string(syslog_msg, OS_SIZE_2048, " dstcity: %s;", al_data->dstgeoip);
#endif
        field_add_string(syslog_msg, OS_SIZE_2048, " dstip: %s;", al_data->dstip);
        field_add_string(syslog_msg, OS_SIZE_2048, " user: %s;", al_data->user);
        field_add_string(syslog_msg, OS_SIZE_2048, " Previous MD5: %s;", al_data->old_md5);
        field_add_string(syslog_msg, OS_SIZE_2048, " Current MD5: %s;", al_data->new_md5);
        field_add_string(syslog_msg, OS_SIZE_2048, " Previous SHA1: %s;", al_data->old_sha1);
        field_add_string(syslog_msg, OS_SIZE_2048, " Current SHA1: %s;", al_data->new_sha1);
        /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
        field_add_string(syslog_msg, OS_SIZE_2048, " Size changed: from %s;", al_data->file_size);
        field_add_string(syslog_msg, OS_SIZE_2048, " User ownership: was %s;", al_data->owner_chg);
        field_add_string(syslog_msg, OS_SIZE_2048, " Group ownership: was %s;", al_data->group_chg);
        field_add_string(syslog_msg, OS_SIZE_2048, " Permissions changed: from %s;", al_data->perm_chg);
        /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
        field_add_truncated(syslog_msg, OS_SIZE_2048, " %s", logmsg, 2);
    } else if (syslog_config->format == CEF_CSYSLOG) {
        /* Start with headers */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s CEF:0|%s|%s|%s|%u|%s|%u|",
                 syslog_config->priority,
                 tstamp,
                 __author,
                 __ossec_name,
                 __version,
                 al_data->rule,
                 cefescape(al_data->comment, true),
                 (al_data->level > 10) ? 10 : al_data->level);
        /* Add extensions */
        field_add_string(syslog_msg, OS_SIZE_2048, "dvc=%s", cefescape(hostname, false));
        field_add_string(syslog_msg, OS_SIZE_2048, " cs1Label=Location cs1=%s", cefescape(al_data->location, false));
        field_add_string(syslog_msg, OS_SIZE_2048, " classification=%s", cefescape(al_data->group, false));
        field_add_string(syslog_msg, OS_SIZE_2048, " src=%s", al_data->srcip);
        field_add_int(syslog_msg, OS_SIZE_2048, " dpt=%d", al_data->dstport);
        field_add_int(syslog_msg, OS_SIZE_2048, " spt=%d", al_data->srcport);
        field_add_string(syslog_msg, OS_SIZE_2048, " fname=%s", cefescape(al_data->filename, false));
        field_add_string(syslog_msg, OS_SIZE_2048, " dhost=%s", al_data->dstip);
        field_add_string(syslog_msg, OS_SIZE_2048, " shost=%s", al_data->srcip);
        field_add_string(syslog_msg, OS_SIZE_2048, " suser=%s", cefescape(al_data->user, false));
        field_add_string(syslog_msg, OS_SIZE_2048, " dst=%s", cefescape(al_data->dstip, false));
#ifdef LIBGEOIP_ENABLED
        field_add_string(syslog_msg, OS_SIZE_2048, " cs4Label=SrcCity cs4=%s", cefescape(al_data->srcgeoip, false));
        field_add_string(syslog_msg, OS_SIZE_2048, " cs5Label=DstCity cs5=%s", cefescape(al_data->dstgeoip, false));
#endif
        if (al_data->new_md5 && al_data->new_sha1) {
            field_add_string(syslog_msg, OS_SIZE_2048, " cs2Label=OldMD5 cs2=%s", al_data->old_md5);
            field_add_string(syslog_msg, OS_SIZE_2048, " cs3Label=NewMD5 cs3=%s", al_data->new_md5);
            field_add_string(syslog_msg, OS_SIZE_2048, " oldFileHash=%s", al_data->old_sha1);
            field_add_string(syslog_msg, OS_SIZE_2048, " fhash=%s", al_data->new_sha1);
            field_add_string(syslog_msg, OS_SIZE_2048, " fileHash=%s", al_data->new_sha1);
        }
        field_add_truncated(syslog_msg, OS_SIZE_2048, " msg=%s", cefescape(logmsg, false), 2);
        cefescape(NULL,0);  /* Clean up the escaping buffer */
    } else if (syslog_config->format == JSON_CSYSLOG) {
        /* Build a JSON Object for logging */
        cJSON *root;
        char *json_string;
        root = cJSON_CreateObject();

        /* Data guaranteed to be there */
        cJSON_AddNumberToObject(root, "crit",      al_data->level);
        cJSON_AddNumberToObject(root, "id",        al_data->rule);
        cJSON_AddStringToObject(root, "component", al_data->location);

        /* Rule Meta Data */
        if (al_data->group) {
            cJSON_AddStringToObject(root, "classification", al_data->group);
        }
        if (al_data->comment) {
            cJSON_AddStringToObject(root, "description",    al_data->comment);
        }

        /* Raw log message generating event */
        if (logmsg) {
            cJSON_AddStringToObject(root, "message",  logmsg);
        }

        /* Add data if it exists */
        if (al_data->user) {
            cJSON_AddStringToObject(root, "acct",     al_data->user);
        }
        if (al_data->srcip) {
            cJSON_AddStringToObject(root, "src_ip",   al_data->srcip);
        }
        if (al_data->srcport) {
            cJSON_AddNumberToObject(root, "src_port", al_data->srcport);
        }
        if (al_data->dstip) {
            cJSON_AddStringToObject(root, "dst_ip",   al_data->dstip);
        }
        if (al_data->dstport) {
            cJSON_AddNumberToObject(root, "dst_port", al_data->dstport);
        }
        if (al_data->filename) {
            cJSON_AddStringToObject(root, "file",     al_data->filename);
        }
        if (al_data->old_md5) {
            cJSON_AddStringToObject(root, "md5_old",  al_data->old_md5);
        }
        if (al_data->new_md5) {
            cJSON_AddStringToObject(root, "md5_new",  al_data->new_md5);
        }
        if (al_data->old_sha1) {
            cJSON_AddStringToObject(root, "sha1_old", al_data->old_sha1);
        }
        if (al_data->new_sha1) {
            cJSON_AddStringToObject(root, "sha1_new", al_data->new_sha1);
        }
#ifdef LIBGEOIP_ENABLED
        if (al_data->srcgeoip) {
            cJSON_AddStringToObject(root, "src_city", al_data->srcgeoip);
        }
        if (al_data->dstgeoip) {
            cJSON_AddStringToObject(root, "dst_city", al_data->dstgeoip);
        }
#endif

        /* Create the JSON string */
        json_string = cJSON_PrintUnformatted(root);

        /* Create the syslog message */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s %s ossec: %s",

                 /* syslog header */
                 syslog_config->priority, tstamp, hostname,

                 /* JSON Encoded Data */
                 json_string
                );
        /* Clean up the memory for the JSON structure */
        free(json_string);
        cJSON_Delete(root);
    } else if (syslog_config->format == SPLUNK_CSYSLOG) {
        /* Build a Splunk Style Key/Value string for logging */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s %s ossec: crit=%u id=%u description=\"%s\" component=\"%s\",",

                 /* syslog header */
                 syslog_config->priority, tstamp, hostname,

                 /* OSSEC metadata */
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location
                );
        /* Event specifics */
        field_add_string(syslog_msg, OS_SIZE_2048, " classification=\"%s\",", al_data->group);

        if (field_add_string(syslog_msg, OS_SIZE_2048, " src_ip=\"%s\",", al_data->srcip) > 0) {
            field_add_int(syslog_msg, OS_SIZE_2048, " src_port=%d,", al_data->srcport);
        }

#ifdef LIBGEOIP_ENABLED
        field_add_string(syslog_msg, OS_SIZE_2048, " src_city=\"%s\",", al_data->srcgeoip);
        field_add_string(syslog_msg, OS_SIZE_2048, " dst_city=\"%s\",", al_data->dstgeoip);
#endif

        if (field_add_string(syslog_msg, OS_SIZE_2048, " dst_ip=\"%s\",", al_data->dstip) > 0) {
            field_add_int(syslog_msg, OS_SIZE_2048, " dst_port=%d,", al_data->dstport);
        }

        field_add_string(syslog_msg, OS_SIZE_2048, " file=\"%s\",", al_data->filename);
        field_add_string(syslog_msg, OS_SIZE_2048, " acct=\"%s\",", al_data->user);
        field_add_string(syslog_msg, OS_SIZE_2048, " md5_old=\"%s\",", al_data->old_md5);
        field_add_string(syslog_msg, OS_SIZE_2048, " md5_new=\"%s\",", al_data->new_md5);
        field_add_string(syslog_msg, OS_SIZE_2048, " sha1_old=\"%s\",", al_data->old_sha1);
        field_add_string(syslog_msg, OS_SIZE_2048, " sha1_new=\"%s\",", al_data->new_sha1);
        /* Message */
        field_add_truncated(syslog_msg, OS_SIZE_2048, " message=\"%s\"", logmsg, 2);
    }

    OS_SendUDPbySize(syslog_config->socket, strlen(syslog_msg), syslog_msg);
    return (1);
}

