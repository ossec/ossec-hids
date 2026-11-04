/* Copyright (C) 2012 Daniel B. Cid (http://dcid.me)
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "headers/read-alert.h"
#include "logcollector.h"
#include "ossecalert_field.h"


/* Forward the next alert of the file. Returns 0 if there is none. */
static int read_next_ossecalert(int pos, int drop_it)
{
    alert_data *al_data;
    char user_msg[256];
    char srcip_msg[256];
    char syslog_msg[OS_SIZE_2048 + 1];
    fpos_t fp_pos;

    /* GetAlertData() does not rewind a torn trailing record. Save the
     * offset so a drain that hits EOF mid-alert leaves those bytes for
     * the next poll (same pattern as read_syslog / read_multiline).
     */
    fgetpos(logff[pos].fp, &fp_pos);
    al_data = GetAlertData(0, logff[pos].fp);
    if (!al_data) {
        fsetpos(logff[pos].fp, &fp_pos);
        clearerr(logff[pos].fp);
        return (0);
    }

    memset(syslog_msg, '\0', OS_SIZE_2048 + 1);

    /* Keep ';' out of values: the central OSSECAlert decoder ends each
     * field at the next ';' with no escape (ANT-2026-8TB11KJO). */
    OS_OaCleanField(al_data->comment);
    OS_OaCleanField(al_data->location);
    OS_OaCleanField(al_data->srcip);
    OS_OaCleanField(al_data->user);

    /* Add source ip (cut so the closing ';' always fits) */
    if (!al_data->srcip ||
            ((al_data->srcip[0] == '(') &&
             (al_data->srcip[1] == 'n') &&
             (al_data->srcip[2] == 'o'))) {
        srcip_msg[0] = '\0';
    } else if (OS_OaFormatTaggedField(srcip_msg, sizeof(srcip_msg),
                                      "srcip", al_data->srcip) != 0) {
        srcip_msg[0] = '\0';
    }

    /* Add username (cut so the closing ';' always fits) */
    if (!al_data->user ||
            ((al_data->user[0] == '(') &&
             (al_data->user[1] == 'n') &&
             (al_data->user[2] == 'o'))) {
        user_msg[0] = '\0';
    } else if (OS_OaFormatTaggedField(user_msg, sizeof(user_msg),
                                      "user", al_data->user) != 0) {
        user_msg[0] = '\0';
    }

    if (al_data->log[1] == NULL) {
        /* Build syslog message */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "ossec: Alert Level: %d; Rule: %d - %s; "
                 "Location: %s;%s%s  %s",
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location,
                 srcip_msg,
                 user_msg,
                 al_data->log[0]);
    } else {
        char *tmp_msg = NULL;
        short int j = 0;

        while (al_data->log[j] != NULL) {
            tmp_msg = os_LoadString(tmp_msg, al_data->log[j]);
            tmp_msg = os_LoadString(tmp_msg, "\n");
            if (tmp_msg == NULL) {
                FreeAlertData(al_data);
                return (0);
            }
            j++;
        }

        if (tmp_msg == NULL) {
            FreeAlertData(al_data);
            return (0);
        }

        if (strlen(tmp_msg) > 1596) {
            tmp_msg[1594] = '.';
            tmp_msg[1595] = '.';
            tmp_msg[1596] = '.';
            tmp_msg[1597] = '\0';
        }
        snprintf(syslog_msg, OS_SIZE_2048,
                 "ossec: Alert Level: %d; Rule: %d - %s; "
                 "Location: %s;%s%s  %s",
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location,
                 srcip_msg,
                 user_msg,
                 tmp_msg);

        free(tmp_msg);
    }

    /* Clear the memory */
    FreeAlertData(al_data);

    /* Send message to queue */
    if (drop_it == 0) {
        if (SendMSG(logr_queue, syslog_msg, logff[pos].file, LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND, ARGV0);
            if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }
        }
    }

    return (1);
}

/* Read OSSEC alert files */
void *read_ossecalert(int pos, int *rc, int drop_it)
{
    *rc = 0;

    /* Forward every available alert, as the line readers do: the daemon
     * loop only calls us once per loop_timeout. Count each alert against
     * logcollector.max_lines so one alerts.log cannot starve the rest
     * (ANT-2026-1HUE1BMJ / ANT-2026-54AZKAI7).
     */
    while (logr_consume_line(drop_it)) {
        if (!read_next_ossecalert(pos, drop_it)) {
            break;
        }
    }

    return (NULL);
}
