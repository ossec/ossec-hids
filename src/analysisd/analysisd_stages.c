/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include "queue_op.h"
#endif

#include "shared.h"
#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "stats.h"
#include "eventinfo.h"
#include "accumulator.h"
#include "analysisd.h"
#include "fts.h"
#include "cleanevent.h"
#include "output/jsonout.h"
#include "pipeline.h"
#include "state.h"
#include "alerts/log.h"

#ifdef PRELUDE_OUTPUT_ENABLED
#include "output/prelude.h"
#endif

#ifdef ZEROMQ_OUTPUT_ENABLED
#include "output/zeromq.h"
#endif

extern int analysisd_execdq;
extern int analysisd_arq;
extern RuleInfo *analysisd_stats_rule;
extern int hourly_events;
extern int hourly_syscheck;
extern int hourly_firewall;

#ifndef WIN32
extern os_queue *writer_queue_log;
extern os_queue *writer_queue_statistical;
extern os_queue *writer_queue_archive;
extern os_queue *writer_queue_firewall;
static int archive_drop_warned = 0;
static pthread_mutex_t hour_rollover_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Snapshot leftover rule->last_events onto the async alert copy (fallback if
 * Search/doDiff already moved context onto the live event). Then clear the
 * live RuleInfo buffer under rule->mutex. */
static void analysisd_snapshot_rule_last_events(Eventinfo *dst, RuleInfo *rule)
{
    if (!dst || !rule) {
        return;
    }

    /* Already claimed onto the live event and deep-copied onto dst. */
    if (dst->alert_last_events) {
        return;
    }

    if (!rule->last_events) {
        return;
    }

    os_mutex_lock(&rule->mutex);
    if (!rule->last_events || !rule->last_events_copied) {
        os_mutex_unlock(&rule->mutex);
        return;
    }

    OS_MoveRuleLastEvents(rule, dst);
    os_mutex_unlock(&rule->mutex);
}
#endif

extern void DecodeEvent(Eventinfo *lf, regex_matching *decoder_match);
extern int DecodeSyscheck(Eventinfo *lf);
extern int DecodeRootcheck(Eventinfo *lf);
extern int DecodeHostinfo(Eventinfo *lf);
extern RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node);
extern void DumpLogstats(void);

Eventinfo *analysisd_event_alloc(void)
{
    Eventinfo *lf = (Eventinfo *)calloc(1, sizeof(Eventinfo));

    if (!lf) {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }

    os_calloc(Config.decoder_order_size, sizeof(char *), lf->fields);
    return lf;
}

void analysisd_set_time_context(Eventinfo *lf)
{
    struct tm tm_buf;
    struct tm *p;

    c_time = lf->time;
    p = localtime_r(&c_time, &tm_buf);
    if (!p) {
        return;
    }
    __crt_hour = p->tm_hour;
    __crt_wday = p->tm_wday;
}

int analysisd_handle_hour_rollover(Eventinfo *lf)
{
#ifndef WIN32
    os_mutex_lock(&hour_rollover_mutex);
#endif
    if (thishour != __crt_hour) {
        DumpLogstats();
        thishour = __crt_hour;

        if (today != lf->day) {
            if (Config.stats) {
                Update_Hour();
            }

            if (OS_GetLogLocation(lf) < 0) {
#ifndef WIN32
                os_mutex_unlock(&hour_rollover_mutex);
#endif
                ErrorExit("%s: Error allocating log files", ARGV0);
            }

            today = lf->day;
            strncpy(prev_month, lf->mon, 3);
            prev_year = lf->year;
        }
    }
#ifndef WIN32
    os_mutex_unlock(&hour_rollover_mutex);
#endif

    return 0;
}

Eventinfo *analysisd_decode_event(Eventinfo *lf, char mq_prefix, regex_matching *decoder_match)
{
    if (mq_prefix == SYSCHECK_MQ) {
        analysisd_inc_hourly_syscheck();

        if (!DecodeSyscheck(lf)) {
            Free_Eventinfo(lf);
            return NULL;
        }

        lf->size = strlen(lf->log);
    } else if (mq_prefix == ROOTCHECK_MQ) {
        if (!DecodeRootcheck(lf)) {
            Free_Eventinfo(lf);
            return NULL;
        }
        lf->size = strlen(lf->log);
    } else if (mq_prefix == HOSTINFO_MQ) {
        if (!DecodeHostinfo(lf)) {
            Free_Eventinfo(lf);
            return NULL;
        }
        lf->size = strlen(lf->log);
    } else {
        lf->size = strlen(lf->log);
        DecodeEvent(lf, decoder_match);
    }

    if (lf->decoder_info && lf->decoder_info->type == FIREWALL) {
        analysisd_inc_hourly_firewall();
        if (Config.logfw) {
            /* Incomplete firewall events are dropped (same as FW_Log). */
            if (!lf->action || !lf->srcip || !lf->dstip || !lf->protocol) {
                Free_Eventinfo(lf);
                return NULL;
            }

            /* Normalize on the live event so rule matching sees DROP/ALLOW. */
            FW_NormalizeAction(lf);
#ifndef WIN32
            if (writer_queue_firewall) {
                Eventinfo *fw_copy = analysisd_copy_event_for_log(lf);

                if (fw_copy && os_queue_push_ex_block(writer_queue_firewall, fw_copy) != 0) {
                    Free_Eventinfo(fw_copy);
                    FW_Log(lf);
                }
            } else
#endif
            {
                FW_Log(lf);
            }
        }
    }

    return lf;
}

int analysisd_analyze_event(Eventinfo *lf)
{
    RuleNode *rulenode_pt;
    int owned_by_writer = 0;

    if (!lf || !lf->decoder_info) {
        return 0;
    }

    /* Flood window is TLS per process/match shard (no global lastmsg_mutex). */
    if (lf->decoder_info->type == SYSLOG) {
        if (LastMsg_Stats(lf->full_log) == 1) {
            return 0;
        }
        LastMsg_Change(lf->full_log);
    }

    if (lf->decoder_info->accumulate == 1) {
        lf = Accumulate(lf);
        if (!lf || !lf->decoder_info) {
            return 0;
        }
    }

    analysisd_set_time_context(lf);
    currently_rule = NULL;
    analysisd_handle_hour_rollover(lf);

    /* Check_Hour excessive-events alerts use a dedicated statistical writer so
     * they do not contend with the normal alerts queue (Nested parity). */
    if (Config.stats && Check_Hour() == 1 && analysisd_stats_rule) {
        RuleInfo *saved_rule = lf->generated_rule;
        char *saved_log = lf->full_log;

        lf->generated_rule = analysisd_stats_rule;
        lf->full_log = __stats_comment;

        if (analysisd_stats_rule->alert_opts & DO_LOGALERT) {
#ifndef WIN32
            if (writer_queue_statistical) {
                Eventinfo *alert_copy;

                lf->alert_id = analysisd_claim_alert_id();
                alert_copy = analysisd_copy_event_for_log(lf);
                if (alert_copy) {
                    analysisd_snapshot_rule_last_events(alert_copy, analysisd_stats_rule);
                    if (analysisd_enqueue_statistical(alert_copy) != 0) {
                        Free_Eventinfo(alert_copy);
                        analysisd_inc_alerts_dropped();
                    }
                }
            } else
#endif
            {
                __crt_ftell = _aflog ? ftell(_aflog) : 0;
                if (Config.custom_alert_output) {
                    OS_CustomLog(lf, Config.custom_alert_output_format);
                } else {
                    OS_Log(lf);
                }
                if (Config.jsonout_output) {
                    jsonout_output_event(lf);
                }
            }
        }

        lf->generated_rule = saved_rule;
        lf->full_log = saved_log;
    }

    DEBUG_MSG("%s: DEBUG: Checking the rules - %d ", ARGV0, lf->decoder_info->type);

    rulenode_pt = OS_GetFirstRule();
    if (!rulenode_pt) {
        ErrorExit("%s: Rules in an inconsistent state. Exiting.", ARGV0);
    }

    do {
        if (lf->decoder_info->type == OSSEC_ALERT) {
            if (!lf->generated_rule) {
                return 0;
            }
            currently_rule = lf->generated_rule;
        } else if (rulenode_pt->ruleinfo->category != lf->decoder_info->type) {
            continue;
        } else if ((currently_rule = OS_CheckIfRuleMatch(lf, rulenode_pt)) == NULL) {
            continue;
        }

        if (currently_rule->level == 0) {
            break;
        }

        if (currently_rule->ignore_time) {
            int skip_ignore = 0;

            os_mutex_lock(&currently_rule->mutex);
            if (currently_rule->time_ignored == 0) {
                currently_rule->time_ignored = lf->time;
            } else if ((lf->time - currently_rule->time_ignored) < currently_rule->ignore_time) {
                skip_ignore = 1;
            } else {
                currently_rule->time_ignored = lf->time;
            }
            os_mutex_unlock(&currently_rule->mutex);
            if (skip_ignore) {
                break;
            }
        }

        lf->generated_rule = currently_rule;

        if (currently_rule->ckignore && IGnore(lf)) {
            lf->generated_rule = NULL;
            break;
        }

        if (currently_rule->ignore) {
            AddtoIGnore(lf);
        }

        if (currently_rule->alert_opts & DO_LOGALERT) {
#ifndef WIN32
            if (writer_queue_log) {
                Eventinfo *alert_copy;

                lf->alert_id = analysisd_claim_alert_id();
                alert_copy = analysisd_copy_event_for_log(lf);
                if (alert_copy) {
                    analysisd_snapshot_rule_last_events(alert_copy, currently_rule);
                    if (analysisd_enqueue_alert(alert_copy) != 0) {
                        Free_Eventinfo(alert_copy);
                        analysisd_inc_alerts_dropped();
                    }
                }
            } else
#endif
            {
                __crt_ftell = _aflog ? ftell(_aflog) : 0;
                if (Config.custom_alert_output) {
                    OS_CustomLog(lf, Config.custom_alert_output_format);
                } else {
                    OS_Log(lf);
                }
                if (Config.jsonout_output) {
                    jsonout_output_event(lf);
                }
#ifndef WIN32
                analysisd_inc_alerts_written();
#endif
            }
        }

#ifdef PRELUDE_OUTPUT_ENABLED
        if (Config.prelude && Config.prelude_log_level <= currently_rule->level) {
            OS_PreludeLog(lf);
        }
#endif

#ifdef ZEROMQ_OUTPUT_ENABLED
        if (Config.zeromq_output) {
            zeromq_output_event(lf);
        }
#endif

        if (currently_rule->ar) {
            active_response **rule_ar = currently_rule->ar;

            while (*rule_ar) {
                int do_ar = 1;

                if ((*rule_ar)->ar_cmd->expect & USERNAME) {
                    if (!lf->dstuser || !OS_PRegex(lf->dstuser, "^[a-zA-Z._0-9@?-]*$")) {
                        if (lf->dstuser) {
                            merror(CRAFTED_USER, ARGV0, lf->dstuser);
                        }
                        do_ar = 0;
                    }
                }
                if ((*rule_ar)->ar_cmd->expect & SRCIP) {
                    if (!lf->srcip || !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$")) {
                        if (lf->srcip) {
                            merror(CRAFTED_IP, ARGV0, lf->srcip);
                        }
                        do_ar = 0;
                    }
                }
                if ((*rule_ar)->ar_cmd->expect & FILENAME) {
                    if (!lf->filename) {
                        do_ar = 0;
                    }
                }

                if (do_ar && analysisd_execdq > 0) {
                    OS_Exec(analysisd_execdq, analysisd_arq, lf, *rule_ar);
                }
                rule_ar++;
            }
        }

        if (currently_rule->sid_prev_matched) {
            os_mutex_lock(&currently_rule->mutex);
            if (!OSList_AddData(currently_rule->sid_prev_matched, lf)) {
                merror("%s: Unable to add data to sig list.", ARGV0);
            } else {
                lf->sid_node_to_delete = currently_rule->sid_prev_matched->last_node;
            }
            os_mutex_unlock(&currently_rule->mutex);
        } else if (currently_rule->group_prev_matched) {
            unsigned int j = 0;

            os_mutex_lock(&currently_rule->mutex);
            while (j < currently_rule->group_prev_matched_sz) {
                if (!OSList_AddData(currently_rule->group_prev_matched[j], lf)) {
                    merror("%s: Unable to add data to grp list.", ARGV0);
                }
                j++;
            }
            os_mutex_unlock(&currently_rule->mutex);
        }

        OS_AddEvent(lf);
        break;
    } while ((rulenode_pt = rulenode_pt->next) != NULL);

    if (Config.logall) {
#ifndef WIN32
        if (writer_queue_archive) {
            /* No rule matched: EventList will not retain lf — transfer ownership
             * to the archive writer instead of deep-copying. Matched events keep
             * a deep copy because OS_AddEvent still owns the live Eventinfo. */
            if (lf->generated_rule == NULL) {
                if (os_queue_push_ex(writer_queue_archive, lf) == 0) {
                    owned_by_writer = 1;
                } else {
                    analysisd_inc_archives_dropped();
                    if (!archive_drop_warned) {
                        merror("%s: WARN: Dropping archive events: archive queue full "
                               "(logall best-effort under backlog).", ARGV0);
                        archive_drop_warned = 1;
                    }
                }
            } else {
                Eventinfo *arch_copy = analysisd_copy_event_for_log(lf);

                if (arch_copy && os_queue_push_ex(writer_queue_archive, arch_copy) != 0) {
                    Free_Eventinfo(arch_copy);
                    analysisd_inc_archives_dropped();
                    if (!archive_drop_warned) {
                        merror("%s: WARN: Dropping archive events: archive queue full "
                               "(logall best-effort under backlog).", ARGV0);
                        archive_drop_warned = 1;
                    }
                }
            }
        } else
#endif
        {
            OS_Store(lf);
            if (Config.logall_json) {
                jsonout_output_archive(lf);
            }
        }
    } else if (Config.logall_json) {
        jsonout_output_archive(lf);
    }

    return owned_by_writer;
}

void analysisd_finish_event(Eventinfo *lf)
{
    if (lf && lf->generated_rule == NULL) {
        Free_Eventinfo(lf);
    }
}
