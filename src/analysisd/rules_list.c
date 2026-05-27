/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "eventinfo.h"

/* Rulenode local  */
static RuleNode *rulenode;
static RuleNode *rulenode_staging;
static int rulelist_staging_active;

static RuleNode **rulelist_head(void)
{
    if (rulelist_staging_active) {
        return (&rulenode_staging);
    }
    return (&rulenode);
}

/* Track heap pointers already released while tearing down a rule tree */
static OSHash *rule_free_seen;

static int rule_ptr_already_freed(const void *ptr)
{
    char key[32];

    if (!ptr || !rule_free_seen) {
        return (0);
    }

    snprintf(key, sizeof(key), "%p", ptr);
    return (OSHash_Get(rule_free_seen, key) != NULL);
}

static void rule_ptr_mark_freed(const void *ptr)
{
    char key[32];

    if (!ptr || !rule_free_seen) {
        return;
    }

    snprintf(key, sizeof(key), "%p", ptr);
    OSHash_Add(rule_free_seen, key, (void *)1);
}

static void free_str_field(char **field)
{
    if (*field && !rule_ptr_already_freed(*field)) {
        free(*field);
        rule_ptr_mark_freed(*field);
    }
    *field = NULL;
}

static void free_osmatch_field(OSMatch **field)
{
    if (*field && !rule_ptr_already_freed(*field)) {
        OSMatch_FreePattern(*field);
        free(*field);
        rule_ptr_mark_freed(*field);
    }
    *field = NULL;
}

static void free_osregex_field(OSRegex **field)
{
    if (*field && !rule_ptr_already_freed(*field)) {
        OSRegex_FreePattern(*field);
        free(*field);
        rule_ptr_mark_freed(*field);
    }
    *field = NULL;
}

static void free_ospcre2_field(OSPcre2 **field)
{
    if (*field && !rule_ptr_already_freed(*field)) {
        OSPcre2_FreePattern(*field);
        free(*field);
        rule_ptr_mark_freed(*field);
    }
    *field = NULL;
}

static void free_osip_field(os_ip **field)
{
    if (*field && !rule_ptr_already_freed(*field)) {
        free(*field);
        rule_ptr_mark_freed(*field);
    }
    *field = NULL;
}

/* _OS_Addrule: Internal AddRule */
static RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule);
static int _AddtoRule(int sid, int level, int none, const char *group,
               RuleNode *r_node, RuleInfo *read_rule);
static void destroy_rule_tree(RuleNode *tree);

#define RULELIST_FAIL(...) do {                                         \
        if (rulelist_staging_active) {                                  \
            merror(__VA_ARGS__);                                        \
            return (-1);                                                \
        }                                                               \
        ErrorExit(__VA_ARGS__);                                         \
    } while (0)

#define RULELIST_PTR_FAIL(...) do {                                     \
        if (rulelist_staging_active) {                                  \
            merror(__VA_ARGS__);                                        \
            return (NULL);                                              \
        }                                                               \
        ErrorExit(__VA_ARGS__);                                         \
    } while (0)

#define RULELIST_MARK_FAIL(...) do {                                    \
        if (rulelist_staging_active) {                                  \
            merror(__VA_ARGS__);                                        \
            return (-1);                                                \
        }                                                               \
        ErrorExit(__VA_ARGS__);                                         \
    } while (0)

static int os_addrule_child(RuleNode *r_node, RuleInfo *read_rule)
{
    RuleNode *child;

    child = _OS_AddRule(r_node->child, read_rule);
    if (!child) {
        return (-1);
    }

    r_node->child = child;
    return (0);
}

static void *rulelist_realloc(void *ptr, size_t size)
{
    void *p;

    p = realloc(ptr, size);
    if (!p) {
        if (rulelist_staging_active) {
            merror(MEM_ERROR, ARGV0, errno, strerror(errno));
            return (NULL);
        }
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }

    return (p);
}


/* Create the RuleList */
void OS_CreateRuleList()
{
    *rulelist_head() = NULL;
    return;
}

void OS_RuleListStagingBegin(void)
{
    rulelist_staging_active = 1;
    rulenode_staging = NULL;
}

void OS_RuleListStagingCommit(void)
{
    OS_AbandonRuleList();
    rulenode = rulenode_staging;
    rulenode_staging = NULL;
    rulelist_staging_active = 0;
}

void OS_RuleListStagingAbort(void)
{
    RuleNode *staging = rulenode_staging;

    rulenode_staging = NULL;
    rulelist_staging_active = 0;
    destroy_rule_tree(staging);
}

int OS_RuleListStagingActive(void)
{
    return (rulelist_staging_active);
}

/* Free all rules and reset the list */
void OS_AbandonRuleList(void)
{
    rulenode = NULL;
}

static void destroy_rule_tree(RuleNode *tree)
{
    if (!tree) {
        return;
    }

    rule_free_seen = OSHash_Create();
    if (rule_free_seen) {
        OSHash_setSize(rule_free_seen, 4096);
    }
    OS_FreeRuleList(tree);
    if (rule_free_seen) {
        OSHash_Free(rule_free_seen);
        rule_free_seen = NULL;
    }
}

void OS_DestroyRuleList()
{
    destroy_rule_tree(rulenode);
    rulenode = NULL;
}

/* Get first node from rule */
RuleNode *OS_GetFirstRule()
{
    return (*rulelist_head());
}

/* Search all rules, including children */
static int _AddtoRule(int sid, int level, int none, const char *group,
               RuleNode *r_node, RuleInfo *read_rule)
{
    int r_code = 0;

    /* If we don't have the first node, start from
     * the beginning of the list
     */
    if (!r_node) {
        r_node = OS_GetFirstRule();
    }

    while (r_node) {
        /* Check if the sigid matches */
        if (sid) {
            if (r_node->ruleinfo->sigid == sid) {
                /* Assign the category of this rule to the child
                 * as they must match
                 */
                read_rule->category = r_node->ruleinfo->category;

                /* If no context for rule, check if the parent has context
                 * and use that
                 */
                if (!read_rule->last_events && r_node->ruleinfo->last_events) {
                    read_rule->last_events = r_node->ruleinfo->last_events;
                }

                if (os_addrule_child(r_node, read_rule) < 0) {
                    return (-1);
                }
                return (1);
            }
        }

        /* Check if the group matches */
        else if (group) {
            if (OS_WordMatch(group, r_node->ruleinfo->group) &&
                    (r_node->ruleinfo->sigid != read_rule->sigid)) {
                /* If no context for rule, check if the parent has context
                 * and use that
                 */
                if (!read_rule->last_events && r_node->ruleinfo->last_events) {
                    read_rule->last_events = r_node->ruleinfo->last_events;
                }

                /* Loop over all rules until we find it */
                if (os_addrule_child(r_node, read_rule) < 0) {
                    return (-1);
                }
                r_code = 1;
            }
        }

        /* Check if the level matches */
        else if (level) {
            if ((r_node->ruleinfo->level >= level) &&
                    (r_node->ruleinfo->sigid != read_rule->sigid)) {
                if (os_addrule_child(r_node, read_rule) < 0) {
                    return (-1);
                }
                r_code = 1;
            }
        }

        /* If we are not searching for the sid/group, the category must
         * be the same
         */
        else if (read_rule->category != r_node->ruleinfo->category) {
            r_node = r_node->next;
            continue;
        }

        /* If none of them are set, add for the category */
        else {
            /* Set the parent category to it */
            read_rule->category = r_node->ruleinfo->category;
            if (os_addrule_child(r_node, read_rule) < 0) {
                return (-1);
            }
            return (1);
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            int child_rc = _AddtoRule(sid, level, none, group, r_node->child, read_rule);

            if (child_rc < 0) {
                return (-1);
            }
            if (child_rc) {
                r_code = 1;
            }
        }

        r_node = r_node->next;
    }

    return (r_code);
}

/* Add a child */
int OS_AddChild(RuleInfo *read_rule)
{
    if (!read_rule) {
        merror("rules_list: Passing a NULL rule. Inconsistent state");
        return (1);
    }

    /* Adding for if_sid */
    if (read_rule->if_sid) {
        int val = 0;
        const char *sid;

        sid  = read_rule->if_sid;

        /* Loop to read all the rules (comma or space separated) */
        do {
            int rule_id = 0;
            if ((*sid == ',') || (*sid == ' ')) {
                val = 0;
                continue;
            } else if ((isdigit((int)*sid)) || (*sid == '\0')) {
                if (val == 0) {
                    int add_rc;

                    rule_id = atoi(sid);
                    add_rc = _AddtoRule(rule_id, 0, 0, NULL, NULL, read_rule);
                    if (add_rc < 0) {
                        return (-1);
                    }
                    if (!add_rc) {
                        RULELIST_FAIL("rules_list: Signature ID '%d' not "
                                      "found. Invalid 'if_sid'.", rule_id);
                    }
                    val = 1;
                }
            } else {
                RULELIST_FAIL("rules_list: Signature ID must be an integer.");
            }
        } while (*sid++ != '\0');
    }

    /* Adding for if_level */
    else if (read_rule->if_level) {
        int  ilevel = 0;

        ilevel = atoi(read_rule->if_level);
        if (ilevel == 0) {
            merror("%s: Invalid level (atoi)", ARGV0);
            return (1);
        }

        ilevel *= 100;

        {
            int add_rc = _AddtoRule(0, ilevel, 0, NULL, NULL, read_rule);

            if (add_rc < 0) {
                return (-1);
            }
            if (!add_rc) {
                RULELIST_FAIL("rules_list: Level ID '%d' not "
                              "found. Invalid 'if_level'.", ilevel);
            }
        }
    }

    /* Adding for if_group */
    else if (read_rule->if_group) {
        int add_rc = _AddtoRule(0, 0, 0, read_rule->if_group, NULL, read_rule);

        if (add_rc < 0) {
            return (-1);
        }
        if (!add_rc) {
            RULELIST_FAIL("rules_list: Group '%s' not "
                          "found. Invalid 'if_group'.", read_rule->if_group);
        }
    }

    /* Just add based on the category */
    else {
        int add_rc = _AddtoRule(0, 0, 0, NULL, NULL, read_rule);

        if (add_rc < 0) {
            return (-1);
        }
        if (!add_rc) {
            RULELIST_FAIL("rules_list: Category '%d' not "
                          "found. Invalid 'category'.", read_rule->category);
        }
    }

    /* done over here */
    return (0);
}

/* Add a rule in the chain */
static RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule)
{
    RuleNode *tmp_rulenode = _rulenode;

    if (tmp_rulenode != NULL) {
        int middle_insertion = 0;
        RuleNode *prev_rulenode = NULL;
        RuleNode *new_rulenode = NULL;

        while (tmp_rulenode != NULL) {
            if (read_rule->level > tmp_rulenode->ruleinfo->level) {
                middle_insertion = 1;
                break;
            }
            prev_rulenode = tmp_rulenode;
            tmp_rulenode = tmp_rulenode->next;
        }

        new_rulenode = (RuleNode *)calloc(1, sizeof(RuleNode));

        if (!new_rulenode) {
            RULELIST_PTR_FAIL(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        if (middle_insertion == 1) {
            if (prev_rulenode == NULL) {
                _rulenode = new_rulenode;
            } else {
                prev_rulenode->next = new_rulenode;
            }

            new_rulenode->next = tmp_rulenode;
            new_rulenode->ruleinfo = read_rule;
            new_rulenode->child = NULL;
        } else if (prev_rulenode) {
            prev_rulenode->next = new_rulenode;
            new_rulenode->ruleinfo = read_rule;
            new_rulenode->next = NULL;
            new_rulenode->child = NULL;
        } else {
            RuleNode *tail = _rulenode;

            while (tail->next) {
                tail = tail->next;
            }
            tail->next = new_rulenode;
            new_rulenode->ruleinfo = read_rule;
            new_rulenode->next = NULL;
            new_rulenode->child = NULL;
        }
    } else {
        _rulenode = (RuleNode *)calloc(1, sizeof(RuleNode));
        if (_rulenode == NULL) {
            RULELIST_PTR_FAIL(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        _rulenode->ruleinfo = read_rule;
        _rulenode->next = NULL;
        _rulenode->child = NULL;
    }

    return (_rulenode);
}

/* External AddRule */
int OS_AddRule(RuleInfo *read_rule)
{
    RuleNode **head = rulelist_head();
    RuleNode *node;

    node = _OS_AddRule(*head, read_rule);
    if (!node) {
        return (-1);
    }

    *head = node;

    return (0);
}

/* Update rule info for overwritten ones */
int OS_AddRuleInfo(RuleNode *r_node, RuleInfo *newrule, int sid)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        r_node = OS_GetFirstRule();
    }

    if (sid == 0) {
        return (0);
    }

    while (r_node) {
        /* Check if the sigid matches */
        if (r_node->ruleinfo->sigid == sid) {
            r_node->ruleinfo->level = newrule->level;
            r_node->ruleinfo->maxsize = newrule->maxsize;
            r_node->ruleinfo->frequency = newrule->frequency;
            r_node->ruleinfo->timeframe = newrule->timeframe;
            r_node->ruleinfo->ignore_time = newrule->ignore_time;

            r_node->ruleinfo->group = newrule->group;
            r_node->ruleinfo->match = newrule->match;
            r_node->ruleinfo->regex = newrule->regex;
            r_node->ruleinfo->day_time = newrule->day_time;
            r_node->ruleinfo->week_day = newrule->week_day;
            r_node->ruleinfo->srcip = newrule->srcip;
            r_node->ruleinfo->dstip = newrule->dstip;
            r_node->ruleinfo->srcport = newrule->srcport;
            r_node->ruleinfo->dstport = newrule->dstport;
            r_node->ruleinfo->user = newrule->user;
            r_node->ruleinfo->url = newrule->url;
            r_node->ruleinfo->id = newrule->id;
            r_node->ruleinfo->status = newrule->status;
            r_node->ruleinfo->hostname = newrule->hostname;
            r_node->ruleinfo->program_name = newrule->program_name;
            r_node->ruleinfo->extra_data = newrule->extra_data;
            r_node->ruleinfo->action = newrule->action;
            r_node->ruleinfo->comment = newrule->comment;
            r_node->ruleinfo->info = newrule->info;
            r_node->ruleinfo->cve = newrule->cve;
            r_node->ruleinfo->if_matched_regex = newrule->if_matched_regex;
            r_node->ruleinfo->if_matched_group = newrule->if_matched_group;
            r_node->ruleinfo->if_matched_sid = newrule->if_matched_sid;
            r_node->ruleinfo->alert_opts = newrule->alert_opts;
            r_node->ruleinfo->context_opts = newrule->context_opts;
            r_node->ruleinfo->context = newrule->context;
            r_node->ruleinfo->decoded_as = newrule->decoded_as;
            r_node->ruleinfo->ar = newrule->ar;
            r_node->ruleinfo->compiled_rule = newrule->compiled_rule;
            if ((newrule->context_opts & SAME_DODIFF) && r_node->ruleinfo->last_events == NULL) {
                r_node->ruleinfo->last_events = newrule->last_events;
            }

            /* Ownership moved to the existing rule node */
            memset(newrule, 0, sizeof(RuleInfo));

            return (1);
        }


        /* Check if the child has a rule */
        if (r_node->child) {
            if (OS_AddRuleInfo(r_node->child, newrule, sid)) {
                return (1);
            }
        }

        r_node = r_node->next;
    }

    return (0);
}

/* Callback function to mark event node for deletion
 * This is called by OSList when auto-deleting the oldest node
 * to prevent double-free in Free_Eventinfo
 */
static void Mark_EventNodeDelete(void *data)
{
    Eventinfo *lf = (Eventinfo *)data;
    if (lf) {
        /* Clear the sid_node_to_delete pointer to prevent
         * Free_Eventinfo from trying to delete an already-freed node
         */
        lf->sid_node_to_delete = NULL;
    }
}

/* Mark rules that match specific id (for if_matched_sid) */
int OS_MarkID(RuleNode *r_node, RuleInfo *orig_rule)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        r_node = OS_GetFirstRule();
    }

    while (r_node) {
        if (r_node->ruleinfo->sigid == orig_rule->if_matched_sid) {
            /* If child does not have a list, create one */
            if (!r_node->ruleinfo->sid_prev_matched) {
                r_node->ruleinfo->sid_prev_matched = OSList_Create();
                if (!r_node->ruleinfo->sid_prev_matched) {
                    RULELIST_MARK_FAIL(MEM_ERROR, ARGV0, errno, strerror(errno));
                }

                /* Set the callback to clear sid_node_to_delete before auto-deletion
                 * This prevents double-free when the list reaches max size
                 */
                if (!OSList_SetFreeDataPointer(r_node->ruleinfo->sid_prev_matched,
                                                Mark_EventNodeDelete)) {
                    RULELIST_MARK_FAIL("%s: ERROR: Unable to set free data pointer for sid list", ARGV0);
                }
            }

            /* Assign the parent pointer to it */
            orig_rule->sid_search = r_node->ruleinfo->sid_prev_matched;
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            if (OS_MarkID(r_node->child, orig_rule) < 0) {
                return (-1);
            }
        }

        r_node = r_node->next;
    }

    return (0);
}

/* Mark rules that match specific group (for if_matched_group) */
int OS_MarkGroup(RuleNode *r_node, RuleInfo *orig_rule)
{
    /* If no r_node is given, get first node */
    if (r_node == NULL) {
        r_node = OS_GetFirstRule();
    }

    while (r_node) {
        if (OSMatch_Execute(r_node->ruleinfo->group,
                            strlen(r_node->ruleinfo->group),
                            orig_rule->if_matched_group)) {
            unsigned int rule_g = 0;
            if (r_node->ruleinfo->group_prev_matched) {
                while (r_node->ruleinfo->group_prev_matched[rule_g]) {
                    rule_g++;
                }
            }

            r_node->ruleinfo->group_prev_matched = (OSList **)rulelist_realloc(
                r_node->ruleinfo->group_prev_matched,
                (rule_g + 2) * sizeof(OSList *));
            if (!r_node->ruleinfo->group_prev_matched) {
                return (-1);
            }

            r_node->ruleinfo->group_prev_matched[rule_g] = NULL;
            r_node->ruleinfo->group_prev_matched[rule_g + 1] = NULL;

            /* Set the size */
            r_node->ruleinfo->group_prev_matched_sz = rule_g + 1;

            r_node->ruleinfo->group_prev_matched[rule_g] =
                orig_rule->group_search;
        }

        /* Check if the child has a rule */
        if (r_node->child) {
            if (OS_MarkGroup(r_node->child, orig_rule) < 0) {
                return (-1);
            }
        }

        r_node = r_node->next;
    }

    return (0);
}


/* Free a RuleInfo structure and all its members */
void OS_FreeRuleInfo(RuleInfo *rule)
{
    unsigned int i;

    if (!rule) {
        return;
    }

    free_str_field(&rule->group);
    free_str_field(&rule->day_time);
    free_str_field(&rule->week_day);
    free_str_field(&rule->action);
    free_str_field(&rule->comment);
    free_str_field(&rule->info);
    free_str_field(&rule->cve);
    free_str_field(&rule->if_sid);
    free_str_field(&rule->if_level);
    free_str_field(&rule->if_group);

    free_osmatch_field(&rule->match);
    free_ospcre2_field(&rule->match_pcre2);
    free_osregex_field(&rule->regex);
    free_ospcre2_field(&rule->pcre2);

    if (rule->srcip) {
        for (i = 0; rule->srcip[i]; i++) {
            free_osip_field(&rule->srcip[i]);
        }
        if (!rule_ptr_already_freed(rule->srcip)) {
            free(rule->srcip);
            rule_ptr_mark_freed(rule->srcip);
        }
        rule->srcip = NULL;
    }

    if (rule->dstip) {
        for (i = 0; rule->dstip[i]; i++) {
            free_osip_field(&rule->dstip[i]);
        }
        if (!rule_ptr_already_freed(rule->dstip)) {
            free(rule->dstip);
            rule_ptr_mark_freed(rule->dstip);
        }
        rule->dstip = NULL;
    }

    free_osmatch_field(&rule->srcgeoip);
    free_osmatch_field(&rule->dstgeoip);
    free_osmatch_field(&rule->srcport);
    free_osmatch_field(&rule->dstport);
    free_osmatch_field(&rule->user);
    free_osmatch_field(&rule->url);
    free_osmatch_field(&rule->id);
    free_osmatch_field(&rule->status);
    free_osmatch_field(&rule->hostname);
    free_osmatch_field(&rule->program_name);
    free_osmatch_field(&rule->extra_data);

    free_ospcre2_field(&rule->srcgeoip_pcre2);
    free_ospcre2_field(&rule->dstgeoip_pcre2);
    free_ospcre2_field(&rule->srcport_pcre2);
    free_ospcre2_field(&rule->dstport_pcre2);
    free_ospcre2_field(&rule->user_pcre2);
    free_ospcre2_field(&rule->url_pcre2);
    free_ospcre2_field(&rule->id_pcre2);
    free_ospcre2_field(&rule->status_pcre2);
    free_ospcre2_field(&rule->hostname_pcre2);
    free_ospcre2_field(&rule->program_name_pcre2);
    free_ospcre2_field(&rule->extra_data_pcre2);

    free_osregex_field(&rule->if_matched_regex);
    free_osmatch_field(&rule->if_matched_group);

    if (rule->fields) {
        for (i = 0; rule->fields[i]; i++) {
            free_str_field(&rule->fields[i]->name);
            free_osregex_field(&rule->fields[i]->regex);
            if (!rule_ptr_already_freed(rule->fields[i])) {
                free(rule->fields[i]);
                rule_ptr_mark_freed(rule->fields[i]);
            }
        }
        if (!rule_ptr_already_freed(rule->fields)) {
            free(rule->fields);
            rule_ptr_mark_freed(rule->fields);
        }
        rule->fields = NULL;
    }

    if (rule->info_details) {
        RuleInfoDetail *tmp;
        while (rule->info_details) {
            tmp = rule->info_details;
            rule->info_details = rule->info_details->next;
            free_str_field(&tmp->data);
            if (!rule_ptr_already_freed(tmp)) {
                free(tmp);
                rule_ptr_mark_freed(tmp);
            }
        }
    }

    if (rule->lists) {
        ListRule *tmp;
        while (rule->lists) {
            tmp = rule->lists;
            rule->lists = rule->lists->next;
            free_osmatch_field(&tmp->matcher);
            if (!rule_ptr_already_freed(tmp)) {
                free(tmp);
                rule_ptr_mark_freed(tmp);
            }
        }
    }

    if (rule->ar && !rule_ptr_already_freed(rule->ar)) {
        free(rule->ar);
        rule_ptr_mark_freed(rule->ar);
        rule->ar = NULL;
    }

    if (rule->sid_prev_matched && !rule_ptr_already_freed(rule->sid_prev_matched)) {
        OSList_Free(rule->sid_prev_matched);
        rule_ptr_mark_freed(rule->sid_prev_matched);
        rule->sid_prev_matched = NULL;
    }

    if (rule->group_search && !rule_ptr_already_freed(rule->group_search)) {
        OSList_Free(rule->group_search);
        rule_ptr_mark_freed(rule->group_search);
        rule->group_search = NULL;
    }

    if (rule->group_prev_matched) {
        unsigned int g = 0;

        while (rule->group_prev_matched[g]) {
            if (!rule_ptr_already_freed(rule->group_prev_matched[g])) {
                OSList_Free(rule->group_prev_matched[g]);
                rule_ptr_mark_freed(rule->group_prev_matched[g]);
            }
            g++;
        }
        if (!rule_ptr_already_freed(rule->group_prev_matched)) {
            free(rule->group_prev_matched);
            rule_ptr_mark_freed(rule->group_prev_matched);
        }
        rule->group_prev_matched = NULL;
    }

    if (rule->last_events && !rule_ptr_already_freed(rule->last_events)) {
        for (i = 0; i < MAX_LAST_EVENTS; i++) {
            free_str_field(&rule->last_events[i]);
        }
        free(rule->last_events);
        rule_ptr_mark_freed(rule->last_events);
        rule->last_events = NULL;
    }

    if (!rule_ptr_already_freed(rule)) {
        free(rule);
        rule_ptr_mark_freed(rule);
    }
}

/* Free a RuleNode tree recursively.
 * parent_ruleinfo: if_matched_sid children may share last_events with the parent. */
static void OS_FreeRuleList_rec(RuleNode *node, RuleInfo *parent_ruleinfo)
{
    while (node) {
        RuleNode *next = node->next;

        if (node->child) {
            OS_FreeRuleList_rec(node->child, node->ruleinfo);
        }

        if (parent_ruleinfo && node->ruleinfo && node->ruleinfo->last_events &&
                node->ruleinfo->last_events == parent_ruleinfo->last_events) {
            node->ruleinfo->last_events = NULL;
        }

        if (node->ruleinfo) {
            OS_FreeRuleInfo(node->ruleinfo);
        }

        free(node);
        node = next;
    }
}

void OS_FreeRuleList(RuleNode *node)
{
    OS_FreeRuleList_rec(node, NULL);
}
