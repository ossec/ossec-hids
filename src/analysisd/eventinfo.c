/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "correlation_shard.h"

/* Global definitions */
#ifdef TESTRULE
int full_output;
int alert_only;
#endif


/* Free heap-owned frequency context log lines */
void OS_FreeRuleLastEvents(RuleInfo *rule)
{
    int ii;

    if (!rule || !rule->last_events || !rule->last_events_copied) {
        return;
    }

    for (ii = 0; ii <= MAX_LAST_EVENTS; ii++) {
        if (rule->last_events[ii]) {
            free(rule->last_events[ii]);
            rule->last_events[ii] = NULL;
        }
    }

    rule->last_events_copied = 0;
}

/* Store a copy of a log line in the rule frequency context buffer */
void OS_SetRuleLastEvent(RuleInfo *rule, int idx, const char *log)
{
    if (!rule || !rule->last_events || !log) {
        return;
    }

    if (idx < 0 || idx > MAX_LAST_EVENTS) {
        return;
    }

    if (rule->last_events_copied && rule->last_events[idx]) {
        free(rule->last_events[idx]);
        rule->last_events[idx] = NULL;
    }

    os_strdup(log, rule->last_events[idx]);
    rule->last_events_copied = 1;

    if (idx < MAX_LAST_EVENTS) {
        rule->last_events[idx + 1] = NULL;
    }
}

/* Move rule frequency/diff context onto the firing event (caller holds mutex). */
void OS_MoveRuleLastEvents(RuleInfo *rule, Eventinfo *lf)
{
    int i;

    if (!rule || !lf || !rule->last_events || !rule->last_events_copied) {
        return;
    }

    if (lf->alert_last_events) {
        for (i = 0; lf->alert_last_events[i]; i++) {
            free(lf->alert_last_events[i]);
        }
        free(lf->alert_last_events);
        lf->alert_last_events = NULL;
    }

    os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), lf->alert_last_events);
    for (i = 0; i <= MAX_LAST_EVENTS; i++) {
        lf->alert_last_events[i] = rule->last_events[i];
        rule->last_events[i] = NULL;
    }
    rule->last_events_copied = 0;
}


/* Search last times a signature fired
 * Will look for only that specific signature.
 */
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    Eventinfo *ret = NULL;
    OSListNode *lf_node;

    os_mutex_lock(&rule->mutex);

    /* Set frequency to 0 */
    rule->__frequency = 0;
    OS_FreeRuleLastEvents(rule);

    /* Checking if sid search is valid */
    if (!rule->sid_search) {
        merror("%s: ERROR: No sid search.", ARGV0);
        goto out;
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(rule->sid_search);
    if (!lf_node) {
        goto out;
    }
    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if ((my_lf->time - lf->time) > rule->timeframe) {
            goto out;
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            goto out;
        }

        /* Check for same ID */
        if (rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (rule->alert_opts & SAME_EXTRAINFO) {
            /* Check for same source port */
            if (rule->context_opts & SAME_SRCPORT) {
                if ((!lf->srcport) || (!my_lf->srcport)) {
                    continue;
                }

                if (strcmp(lf->srcport, my_lf->srcport) != 0) {
                    continue;
                }
            }

            /* Check for same dst port */
            if (rule->context_opts & SAME_DSTPORT) {
                if ((!lf->dstport) || (!my_lf->dstport)) {
                    continue;
                }

                if (strcmp(lf->dstport, my_lf->dstport) != 0) {
                    continue;
                }
            }

            /* Check for repetitions on user error */
            if (rule->context_opts & SAME_USER) {
                if ((!lf->dstuser) || (!my_lf->dstuser)) {
                    continue;
                }

                if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                    continue;
                }
            }

            /* Check for same location */
            if (rule->context_opts & SAME_LOCATION) {
                if (strcmp(lf->hostname, my_lf->hostname) != 0) {
                    continue;
                }
            }

            /* Check for different URLs */
            if (rule->context_opts & DIFFERENT_URL) {
                if ((!lf->url) || (!my_lf->url)) {
                    continue;
                }

                if (strcmp(lf->url, my_lf->url) == 0) {
                    continue;
                }
            }

            /* GEOIP version of check for repetitions from same src_ip */
            if (rule->context_opts & DIFFERENT_SRCGEOIP) {
                if ((!lf->srcgeoip) || (!my_lf->srcgeoip)) {
                    continue;
                }

                if (strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0) {
                    continue;
                }
            }


        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            goto out;
        }



        /* Check if the number of matches worked */
        if (rule->__frequency <= 10) {
            OS_SetRuleLastEvent(rule, rule->__frequency, lf->full_log);
        }

        if (rule->__frequency < rule->frequency) {
            rule->__frequency++;
            continue;
        }
        rule->__frequency++;


        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;
        first_lf->matched = rule->level;

        ret = lf;
        goto out;

    } while ((lf_node = lf_node->prev) != NULL);

out:
    if (ret) {
        OS_MoveRuleLastEvents(rule, my_lf);
    }
    os_mutex_unlock(&rule->mutex);
    return ret;
}

/* Search last times a group fired
 * Will look for only that specific group on that rule.
 */
Eventinfo *Search_LastGroups(Eventinfo *my_lf, RuleInfo *rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    Eventinfo *ret = NULL;
    OSListNode *lf_node;

    os_mutex_lock(&rule->mutex);

    /* Set frequency to 0 */
    rule->__frequency = 0;
    OS_FreeRuleLastEvents(rule);

    /* Check if sid search is valid */
    if (!rule->group_search) {
        merror("%s: No group search!", ARGV0);
        goto out;
    }

    /* Get last node */
    lf_node = OSList_GetLastNode(rule->group_search);
    if (!lf_node) {
        goto out;
    }
    first_lf = (Eventinfo *)lf_node->data;

    do {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if ((my_lf->time - lf->time) > rule->timeframe) {
            goto out;
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            goto out;
        }

        /* Check for same ID */
        if (rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Grouping of additional data */
        if (rule->alert_opts & SAME_EXTRAINFO) {
            /* Check for same source port */
            if (rule->context_opts & SAME_SRCPORT) {
                if ((!lf->srcport) || (!my_lf->srcport)) {
                    continue;
                }

                if (strcmp(lf->srcport, my_lf->srcport) != 0) {
                    continue;
                }
            }

            /* Check for same dst port */
            if (rule->context_opts & SAME_DSTPORT) {
                if ((!lf->dstport) || (!my_lf->dstport)) {
                    continue;
                }

                if (strcmp(lf->dstport, my_lf->dstport) != 0) {
                    continue;
                }
            }

            /* Check for repetitions on user error */
            if (rule->context_opts & SAME_USER) {
                if ((!lf->dstuser) || (!my_lf->dstuser)) {
                    continue;
                }

                if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                    continue;
                }
            }

            /* Check for same location */
            if (rule->context_opts & SAME_LOCATION) {
                if (strcmp(lf->hostname, my_lf->hostname) != 0) {
                    continue;
                }
            }


            /* Check for different URLs */
            if (rule->context_opts & DIFFERENT_URL) {
                if ((!lf->url) || (!my_lf->url)) {
                    continue;
                }

                if (strcmp(lf->url, my_lf->url) == 0) {
                    continue;
                }
            }


            /* Check for different from same srcgeoip */
            if (rule->context_opts & DIFFERENT_SRCGEOIP) {

                if ((!lf->srcgeoip) || (!my_lf->srcgeoip)) {
                    continue;
                }

                if (strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0) {
                    continue;
                }
            }


        }
        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            goto out;
        }


        /* Check if the number of matches worked */
        if (rule->__frequency < rule->frequency) {
            if (rule->__frequency <= 10) {
                OS_SetRuleLastEvent(rule, rule->__frequency, lf->full_log);
            }

            rule->__frequency++;
            continue;
        }


        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;
        first_lf->matched = rule->level;

        ret = lf;
        goto out;


    } while ((lf_node = lf_node->prev) != NULL);

out:
    if (ret) {
        OS_MoveRuleLastEvents(rule, my_lf);
    }
    os_mutex_unlock(&rule->mutex);
    return ret;
}


/* Look if any of the last events (inside the timeframe)
 * match the specified rule
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *rule)
{
    EventNode *eventnode_pt;
    Eventinfo *lf;
    Eventinfo *first_lf;
    EventList *elist;

    os_mutex_lock(&rule->mutex);
    rule->__frequency = 0;
    OS_FreeRuleLastEvents(rule);

    /* Last events */
    elist = analysisd_get_event_list();
    os_mutex_lock(&elist->mutex);
    eventnode_pt = OS_GetLastEvent_List(elist);
    if (!eventnode_pt) {
        os_mutex_unlock(&elist->mutex);
        os_mutex_unlock(&rule->mutex);
        return (NULL);
    }

    first_lf = (Eventinfo *)eventnode_pt->event;

    /* Search all previous events */
    do {
        lf = eventnode_pt->event;

        /* If time is outside the timeframe, return */
        if ((my_lf->time - lf->time) > rule->timeframe) {
            os_mutex_unlock(&elist->mutex);
            os_mutex_unlock(&rule->mutex);
            return (NULL);
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            os_mutex_unlock(&elist->mutex);
            os_mutex_unlock(&rule->mutex);
            return (NULL);
        }

        /* The category must be the same */
        else if (lf->decoder_info->type != my_lf->decoder_info->type) {
            continue;
        }

        /* If regex does not match, go to next */
        if (rule->if_matched_regex) {
            if (!OSRegex_Execute(lf->log, rule->if_matched_regex)) {
                /* Didn't match */
                continue;
            }
        }

        /* Check for repetitions on user error */
        if (rule->context_opts & SAME_USER) {
            if ((!lf->dstuser) || (!my_lf->dstuser)) {
                continue;
            }

            if (strcmp(lf->dstuser, my_lf->dstuser) != 0) {
                continue;
            }
        }

        /* Check for same ID */
        if (rule->context_opts & SAME_ID) {
            if ((!lf->id) || (!my_lf->id)) {
                continue;
            }

            if (strcmp(lf->id, my_lf->id) != 0) {
                continue;
            }
        }

        /* Check for repetitions from same src_ip */
        if (rule->context_opts & SAME_SRCIP) {
            if ((!lf->srcip) || (!my_lf->srcip)) {
                continue;
            }

            if (strcmp(lf->srcip, my_lf->srcip) != 0) {
                continue;
            }
        }

        /* Check for different urls */
        if (rule->context_opts & DIFFERENT_URL) {
            if ((!lf->url) || (!my_lf->url)) {
                continue;
            }

            if (strcmp(lf->url, my_lf->url) == 0) {
                continue;
            }
        }

        /* Check for different from same srcgeoip */
        if (rule->context_opts & DIFFERENT_SRCGEOIP) {

            if ((!lf->srcgeoip) || (!my_lf->srcgeoip)) {
                continue;
            }

            if (strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0) {
                continue;
            }
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if (lf->matched >= rule->level) {
            os_mutex_unlock(&elist->mutex);
            os_mutex_unlock(&rule->mutex);
            return (NULL);
        }




        /* Check if the number of matches worked */
        if (rule->__frequency < rule->frequency) {
            if (rule->__frequency <= 10) {
                OS_SetRuleLastEvent(rule, rule->__frequency, lf->full_log);
            }

            rule->__frequency++;
            continue;
        }

        /* If reached here, we matched */
        my_lf->matched = rule->level;
        lf->matched = rule->level;
        first_lf->matched = rule->level;

        OS_MoveRuleLastEvents(rule, my_lf);
        os_mutex_unlock(&elist->mutex);
        os_mutex_unlock(&rule->mutex);
        return (lf);

    } while ((eventnode_pt = eventnode_pt->next) != NULL);

    os_mutex_unlock(&elist->mutex);
    os_mutex_unlock(&rule->mutex);
    return (NULL);
}

/* Zero the loginfo structure */
void Zero_Eventinfo(Eventinfo *lf)
{
    /* Free flagged allocations first to prevent memory leaks */
    if (lf->flags & EF_FREE_PNAME) {
        free(lf->program_name);
    }
    if (lf->flags & EF_FREE_HNAME) {
        free(lf->hostname);
    }

    lf->log = NULL;
    lf->full_log = NULL;
    lf->hostname = NULL;
    lf->program_name = NULL;
    lf->location = NULL;

    lf->srcip = NULL;
    lf->srcgeoip = NULL;
    lf->dstip = NULL;
    lf->dstgeoip = NULL;
    lf->srcport = NULL;
    lf->dstport = NULL;
    lf->protocol = NULL;
    lf->action = NULL;
    lf->srcuser = NULL;
    lf->dstuser = NULL;
    lf->id = NULL;
    lf->status = NULL;
    lf->command = NULL;
    lf->url = NULL;
    lf->data = NULL;
    lf->systemname = NULL;

    lf->flags = 0;

    if (lf->fields) {
        int i;
        for (i = 0; i < Config.decoder_order_size; i++) {
            free(lf->fields[i]);
        }
    }

    lf->time = 0;
    lf->matched = 0;

    lf->year = 0;
    lf->mon[3] = '\0';
    lf->hour[9] = '\0';
    lf->day = 0;

    lf->generated_rule = NULL;
    lf->sid_node_to_delete = NULL;
    lf->decoder_info = NULL_Decoder;
    lf->alert_last_events = NULL;
    lf->alert_id = 0;
    lf->tid = 0;
    memset(&lf->queue_in_time, 0, sizeof(lf->queue_in_time));

    lf->filename = NULL;
    lf->perm_before = 0;
    lf->perm_after = 0;
    lf->md5_before = NULL;
    lf->md5_after = NULL;
    lf->sha1_before = NULL;
    lf->sha1_after = NULL;
    lf->sha256_before = NULL;
    lf->sha256_after = NULL;
    lf->size_before = NULL;
    lf->size_after = NULL;
    lf->owner_before = NULL;
    lf->owner_after = NULL;
    lf->gowner_before = NULL;
    lf->gowner_after = NULL;

    return;
}

/* Free the loginfo structure */
void Free_Eventinfo(Eventinfo *lf)
{
    if (!lf) {
        merror("%s: Trying to free NULL event. Inconsistent..", ARGV0);
        return;
    }

    /* full_log is the owned allocation. log usually aliases into it
     * (CleanMSG dual buffer or syscheck log==full_log). Only free log when
     * EF_SEPARATE_LOG marks a distinct malloc. */
    if (lf->log && (lf->flags & EF_SEPARATE_LOG)) {
        free(lf->log);
        lf->flags &= ~EF_SEPARATE_LOG;
    }
    if (lf->full_log) {
        free(lf->full_log);
    }
    lf->full_log = NULL;
    lf->log = NULL;
    if (lf->location) {
        free(lf->location);
    }

    if (lf->srcip) {
        free(lf->srcip);
    }

    if(lf->srcgeoip) {
        free(lf->srcgeoip);
        lf->srcgeoip = NULL;
    }

    if (lf->dstip) {
        free(lf->dstip);
    }

    if(lf->dstgeoip) {
        free(lf->dstgeoip);
        lf->dstgeoip = NULL;
    }

    if (lf->srcport) {
        free(lf->srcport);
    }
    if (lf->dstport) {
        free(lf->dstport);
    }
    if (lf->protocol) {
        free(lf->protocol);
    }
    if (lf->action) {
        free(lf->action);
    }
    if (lf->status) {
        free(lf->status);
    }
    if (lf->srcuser) {
        free(lf->srcuser);
    }
    if (lf->dstuser) {
        free(lf->dstuser);
    }
    if (lf->id) {
        free(lf->id);
    }
    if (lf->command) {
        free(lf->command);
    }
    if (lf->url) {
        free(lf->url);
    }

    if (lf->data) {
        free(lf->data);
    }
    if (lf->systemname) {
        free(lf->systemname);
    }

    if (lf->fields) {
        int i;
        for (i = 0; i < Config.decoder_order_size; i++) {
            free(lf->fields[i]);
        }
        free(lf->fields);
    }

    if (lf->filename) {
        free(lf->filename);
    }
    if (lf->md5_before) {
        free(lf->md5_before);
    }
    if (lf->md5_after) {
        free(lf->md5_after);
    }
    if (lf->sha1_before) {
        free(lf->sha1_before);
    }
    if (lf->sha1_after) {
        free(lf->sha1_after);
    }
    if (lf->sha256_before) {
        free(lf->sha256_before);
    }
    if (lf->sha256_after) {
        free(lf->sha256_after);
    }
    if (lf->size_before) {
        free(lf->size_before);
    }
    if (lf->size_after) {
        free(lf->size_after);
    }
    if (lf->owner_before) {
        free(lf->owner_before);
    }
    if (lf->owner_after) {
        free(lf->owner_after);
    }
    if (lf->gowner_before) {
        free(lf->gowner_before);
    }
    if (lf->gowner_after) {
        free(lf->gowner_after);
    }

    if (lf->alert_last_events) {
        int i;
        for (i = 0; lf->alert_last_events[i]; i++) {
            free(lf->alert_last_events[i]);
        }
        free(lf->alert_last_events);
        lf->alert_last_events = NULL;
    }

    /* Correlation list maintenance belongs to the live event only — async
     * alert/archive/fw copies must not prune shared group/sid lists. */
    if (!(lf->flags & EF_ASYNC_COPY)) {
        /* Free node to delete */
        if (lf->sid_node_to_delete) {
            if (lf->generated_rule) {
#ifndef WIN32
                os_mutex_lock(&lf->generated_rule->mutex);
#endif
                OSList_DeleteThisNode(lf->generated_rule->sid_prev_matched,
                                      lf->sid_node_to_delete);
#ifndef WIN32
                os_mutex_unlock(&lf->generated_rule->mutex);
#endif
            }
            lf->sid_node_to_delete = NULL;
        } else if (lf->generated_rule && lf->generated_rule->group_prev_matched) {
            unsigned int i = 0;

#ifndef WIN32
            os_mutex_lock(&lf->generated_rule->mutex);
#endif
            while (i < lf->generated_rule->group_prev_matched_sz) {
                OSList_DeleteOldestNode(lf->generated_rule->group_prev_matched[i]);
                i++;
            }
#ifndef WIN32
            os_mutex_unlock(&lf->generated_rule->mutex);
#endif
        }
    }

    /* Check if we need to free program_name */
    if (lf->flags & EF_FREE_PNAME) {
        free(lf->program_name);
        lf->program_name = NULL;
        lf->flags &= ~EF_FREE_PNAME;
    }

    /* Check if we need to free hostname */
    if (lf->flags & EF_FREE_HNAME) {
        free(lf->hostname);
        lf->hostname = NULL;
        lf->flags &= ~EF_FREE_HNAME;
    }

    /* We dont need to free:
     * fts
     * comment
     */
    free(lf);
    lf = NULL;
    return;
}

