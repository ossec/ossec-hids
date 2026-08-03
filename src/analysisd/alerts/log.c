/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "log.h"
#include "alerts.h"
#include "getloglocation.h"
#include "rules.h"
#include "eventinfo.h"
#include "config.h"


/* Drop/allow patterns */
static OSMatch FWDROPpm;
static OSMatch FWALLOWpm;

/* Allow custom alert output tokens */
typedef enum e_custom_alert_tokens_id {
    CUSTOM_ALERT_TOKEN_TIMESTAMP = 0,
    CUSTOM_ALERT_TOKEN_FTELL,
    CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS,
    CUSTOM_ALERT_TOKEN_HOSTNAME,
    CUSTOM_ALERT_TOKEN_LOCATION,
    CUSTOM_ALERT_TOKEN_RULE_ID,
    CUSTOM_ALERT_TOKEN_RULE_LEVEL,
    CUSTOM_ALERT_TOKEN_RULE_COMMENT,
    CUSTOM_ALERT_TOKEN_SRC_IP,
    CUSTOM_ALERT_TOKEN_DST_USER,
    CUSTOM_ALERT_TOKEN_FULL_LOG,
    CUSTOM_ALERT_TOKEN_RULE_GROUP,
    CUSTOM_ALERT_TOKEN_LAST
} CustomAlertTokenID;

static const char CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LAST][15] = {
    { "$TIMESTAMP" },
    { "$FTELL" },
    { "$RULEALERT" },
    { "$HOSTNAME" },
    { "$LOCATION" },
    { "$RULEID" },
    { "$RULELEVEL" },
    { "$RULECOMMENT" },
    { "$SRCIP" },
    { "$DSTUSER" },
    { "$FULLLOG" },
    { "$RULEGROUP" },
};

/* Store the events in a file
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 */
void OS_Store(const Eventinfo *lf)
{
    if (strcmp(lf->location, "ossec-keepalive") == 0) {
        return;
    }
    if (strstr(lf->location, "->ossec-keepalive") != NULL) {
        return;
    }

    analysisd_log_io_lock();
    fprintf(_eflog,
            "%d %s %02d %s %s%s%s %s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
            lf->location,
            lf->full_log);

    fflush(_eflog);
    analysisd_log_io_unlock();
    return;
}

void OS_LogOutput(Eventinfo *lf)
{
    /* GeoIP fields are filled at decode time (SrcIP_FP / DstIP_FP). */

    printf(
        "** Alert %ld.%ld:%s - %s\n"
        "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
        (long int)lf->time,
        lf->alert_id ? lf->alert_id : __crt_ftell,
        lf->generated_rule->alert_opts & DO_MAILALERT ? " mail " : "",
        lf->generated_rule->group,
        lf->year,
        lf->mon,
        lf->day,
        lf->hour,
        lf->hostname != lf->location ? lf->hostname : "",
        lf->hostname != lf->location ? "->" : "",
        lf->location,
        lf->generated_rule->sigid,
        lf->generated_rule->level,
        lf->generated_rule->comment,

        lf->srcip == NULL ? "" : "\nSrc IP: ",
        lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
        lf->srcgeoip == NULL ? "" : "\nSrc Location: ",
        lf->srcgeoip == NULL ? "" : lf->srcgeoip,
#else
        "",
        "",
#endif



        lf->srcport == NULL ? "" : "\nSrc Port: ",
        lf->srcport == NULL ? "" : lf->srcport,

        lf->dstip == NULL ? "" : "\nDst IP: ",
        lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
        lf->dstgeoip == NULL ? "" : "\nDst Location: ",
        lf->dstgeoip == NULL ? "" : lf->dstgeoip,
#else
        "",
        "",
#endif



        lf->dstport == NULL ? "" : "\nDst Port: ",
        lf->dstport == NULL ? "" : lf->dstport,

        lf->dstuser == NULL ? "" : "\nUser: ",
        lf->dstuser == NULL ? "" : lf->dstuser,

        lf->full_log);

    /* Print the last events if present */
    {
        char **lasts = lf->alert_last_events ? lf->alert_last_events :
                       (lf->generated_rule ? lf->generated_rule->last_events : NULL);

        if (lasts) {
            while (*lasts) {
                printf("%.1256s\n", *lasts);
                lasts++;
            }
            if (!lf->alert_last_events && lf->generated_rule) {
                os_mutex_lock(&lf->generated_rule->mutex);
                OS_FreeRuleLastEvents(lf->generated_rule);
                os_mutex_unlock(&lf->generated_rule->mutex);
            }
        }
    }

    printf("\n");
    fflush(stdout);
    return;
}

void OS_Log(Eventinfo *lf)
{
    /* GeoIP fields are filled at decode time (SrcIP_FP / DstIP_FP). */

    /* Writing to the alert log file */
    {
        long alert_id = lf->alert_id ? lf->alert_id : __crt_ftell;
        char **lasts = lf->alert_last_events ? lf->alert_last_events :
                       (lf->generated_rule ? lf->generated_rule->last_events : NULL);
        int clear_shared_last_events = 0;

        analysisd_log_io_lock();
        fprintf(_aflog,
                "** Alert %ld.%ld:%s - %s\n"
                "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
                "%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
                (long int)lf->time,
                alert_id,
                lf->generated_rule->alert_opts & DO_MAILALERT ? " mail " : "",
                lf->generated_rule->group,
                lf->year,
                lf->mon,
                lf->day,
                lf->hour,
                lf->hostname != lf->location ? lf->hostname : "",
                lf->hostname != lf->location ? "->" : "",
                lf->location,
                lf->generated_rule->sigid,
                lf->generated_rule->level,
                lf->generated_rule->comment,

                lf->srcip == NULL ? "" : "\nSrc IP: ",
                lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
                lf->srcgeoip == NULL ? "" : "\nSrc Location: ",
                lf->srcgeoip == NULL ? "" : lf->srcgeoip,
#else
                "",
                "",
#endif


                lf->srcport == NULL ? "" : "\nSrc Port: ",
                lf->srcport == NULL ? "" : lf->srcport,

                lf->dstip == NULL ? "" : "\nDst IP: ",
                lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
                lf->dstgeoip == NULL ? "" : "\nDst Location: ",
                lf->dstgeoip == NULL ? "" : lf->dstgeoip,
#else
                "",
                "",
#endif



                lf->dstport == NULL ? "" : "\nDst Port: ",
                lf->dstport == NULL ? "" : lf->dstport,

                lf->dstuser == NULL ? "" : "\nUser: ",
                lf->dstuser == NULL ? "" : lf->dstuser,

                lf->full_log);

        /* Print the last events if present */
        if (lasts) {
            while (*lasts) {
                fprintf(_aflog, "%.1256s\n", *lasts);
                lasts++;
            }
            if (!lf->alert_last_events && lf->generated_rule) {
                clear_shared_last_events = 1;
            }
        }

        fprintf(_aflog, "\n");
        fflush(_aflog);
        analysisd_log_io_unlock();

        /* Free shared rule buffers only after releasing log_io (lock order). */
        if (clear_shared_last_events) {
            os_mutex_lock(&lf->generated_rule->mutex);
            OS_FreeRuleLastEvents(lf->generated_rule);
            os_mutex_unlock(&lf->generated_rule->mutex);
        }
    }

    return;
}

void OS_CustomLog(const Eventinfo *lf, const char *format)
{
    char *log;
    char *tmp_log;
    char tmp_buffer[1024];
    long alert_id = lf->alert_id ? lf->alert_id : __crt_ftell;

    /* Replace all the tokens */
    os_strdup(format, log);

    snprintf(tmp_buffer, 1024, "%ld", (long int)lf->time);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_TIMESTAMP], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }
    snprintf(tmp_buffer, 1024, "%ld", alert_id);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FTELL], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", (lf->generated_rule->alert_opts & DO_MAILALERT) ? "mail " : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->hostname ? lf->hostname : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_HOSTNAME], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->location ? lf->location : "None");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LOCATION], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->sigid);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ID], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->level);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_LEVEL], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->srcip ? lf->srcip : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_SRC_IP], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->dstuser ? lf->dstuser : "None");

    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_DST_USER], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }
    char *escaped_log;
    escaped_log = escape_newlines(lf->full_log);

    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FULL_LOG], escaped_log );
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    if (escaped_log) {
        os_free(escaped_log);
        escaped_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->generated_rule->comment ? lf->generated_rule->comment : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_COMMENT], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->generated_rule->group ? lf->generated_rule->group : "");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_GROUP], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    analysisd_log_io_lock();
    fprintf(_aflog, "%s", log);
    fprintf(_aflog, "\n");
    fflush(_aflog);
    analysisd_log_io_unlock();

    if (log) {
        os_free(log);
        log = NULL;
    }

    return;
}

void OS_InitFwLog()
{
    /* Initialize fw log regexes */
    if (!OSMatch_Compile(FWDROP, &FWDROPpm, 0)) {
        ErrorExit(REGEX_COMPILE, ARGV0, FWDROP,
                  FWDROPpm.error);
    }

    if (!OSMatch_Compile(FWALLOW, &FWALLOWpm, 0)) {
        ErrorExit(REGEX_COMPILE, ARGV0, FWALLOW,
                  FWALLOWpm.error);
    }
}

void FW_NormalizeAction(Eventinfo *lf)
{
    if (!lf || !lf->action) {
        return;
    }

    /* Set the actions */
    switch (*lf->action) {
        /* discard, drop, deny, */
        case 'd':
        case 'D':
        /* reject, */
        case 'r':
        case 'R':
        /* block */
        case 'b':
        case 'B':
            os_free(lf->action);
            os_strdup("DROP", lf->action);
            break;
        /* Closed */
        case 'c':
        case 'C':
        /* Teardown */
        case 't':
        case 'T':
            os_free(lf->action);
            os_strdup("CLOSED", lf->action);
            break;
        /* allow, accept, */
        case 'a':
        case 'A':
        /* pass/permitted */
        case 'p':
        case 'P':
        /* open */
        case 'o':
        case 'O':
            os_free(lf->action);
            os_strdup("ALLOW", lf->action);
            break;
        default:
            if (OSMatch_Execute(lf->action, strlen(lf->action), &FWDROPpm)) {
                os_free(lf->action);
                os_strdup("DROP", lf->action);
            } else if (OSMatch_Execute(lf->action, strlen(lf->action), &FWALLOWpm)) {
                os_free(lf->action);
                os_strdup("ALLOW", lf->action);
            } else {
                os_free(lf->action);
                os_strdup("UNKNOWN", lf->action);
            }
            break;
    }
}

int FW_Log(Eventinfo *lf)
{
    /* If we don't have the srcip or the
     * action, there is no point in going
     * forward over here
     */
    if (!lf->action || !lf->srcip || !lf->dstip || !lf->protocol) {
        return (0);
    }

    FW_NormalizeAction(lf);

    /* Log to file */
    analysisd_log_io_lock();
    fprintf(_fflog,
            "%d %s %02d %s %s%s%s %s %s %s:%s->%s:%s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
            lf->location,
            lf->action,
            lf->protocol,
            lf->srcip,
            lf->srcport ? lf->srcport : "0",
            lf->dstip,
            lf->dstport ? lf->dstport : "0");

    fflush(_fflog);
    analysisd_log_io_unlock();

    return (1);
}

