/* Copyright (C) 2019 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

/* Helper functions */
static void l_print_out(FILE *out, const char *msg, ...)
    __attribute__((format(printf, 2, 3))) __attribute__((nonnull(2)));
static int _os_report_sort_compare(const void *d1, const void *d2) __attribute__((nonnull));
static void _os_header_print(FILE *out, int t, const char *hname) __attribute__((nonnull(3)));
static int _os_report_str_int_compare(const char *str, int id) __attribute__((nonnull));
static int _os_report_check_filters(const alert_data *al_data, const report_filter *r_filter) __attribute__((nonnull));
static int _report_filter_value(const char *filter_by, int prev_filter) __attribute__((nonnull));
static int _os_report_print_related(FILE *out, int print_related, OSList *st_data)
    __attribute__((nonnull(3)));
static int _os_report_add_tostore(const char *key, OSHash *top, void *data) __attribute__((nonnull(1, 2)));
static void _os_report_free_store(OSHash *top) __attribute__((nonnull));


static void l_print_out(FILE *out, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

    if (out) {
        (void)vfprintf(out, msg, args);
        (void)fprintf(out, "\r\n");
    } else {
        (void)vfprintf(stderr, msg, args);
        (void)fprintf(stderr, "\r\n");
    }
    va_end(args);
}

/* More alerts first. Equal counts stay in key order, which is what the
 * old OSStore (inserted by strcmp, then insertion-sorted by count) printed.
 */
static int _os_report_sort_compare(const void *d1, const void *d2)
{
    const OSHashNode *d1n = *(OSHashNode *const *)d1;
    const OSHashNode *d2n = *(OSHashNode *const *)d2;
    const OSList *d1l = (const OSList *)d1n->data;
    const OSList *d2l = (const OSList *)d2n->data;

    if (d1l->currently_size != d2l->currently_size) {
        return ((d1l->currently_size > d2l->currently_size) ? -1 : 1);
    }

    return (strcmp(d1n->key, d2n->key));
}

/* Print output header */
static void _os_header_print(FILE *out, int t, const char *hname)
{
    if (!t) {
        l_print_out(out, "Top entries for '%s':", hname);
        l_print_out(out, "------------------------------------------------");
    } else {
        l_print_out(out, "Related entries for '%s':", hname);
        l_print_out(out, "------------------------------------------------");
    }
}

/* Compare if the id is present in the string */
static int _os_report_str_int_compare(const char *str, int id)
{
    int pt_check = 0;

    do {
        if ((*str == ',') || (*str == ' ')) {
            pt_check = 0;
            continue;
        } else if (*str == '\0') {
            break;
        } else if (isdigit((int)*str)) {
            if (pt_check == 0) {
                if (id == atoi(str)) {
                    return (1);
                }
            }
            pt_check = 1;
        } else {
            return (-1);
        }
    } while (*str++ != '\0');

    return (0);
}

/* Check if the al_data should be filtered */
static int _os_report_check_filters(const alert_data *al_data, const report_filter *r_filter)
{
    /* Check for the filters */
    if (r_filter->group) {
        if (al_data->group) {   /* Probably unnecessary, all (?) alerts should have groups) */
            if (!strstr(al_data->group, r_filter->group)) {
                return (0);
            }
        }
    }
    if (r_filter->rule) {
        if (_os_report_str_int_compare(r_filter->rule, al_data->rule) != 1) {
            return (0);
        }
    }
    if (r_filter->location) {
        if (!OS_Match(r_filter->location, al_data->location)) {
            return (0);
        }
    }
    if (r_filter->level) {
        if (al_data->level < (unsigned int) atoi(r_filter->level)) {
            return (0);
        }
    }
    if (r_filter->srcip) {
        if (!al_data->srcip) {
            return (0);
        }
        if (!strstr(al_data->srcip, r_filter->srcip)) {
            return (0);
        }
    }
    if (r_filter->user) {
        if (!al_data->user) {
            return (0);
        }
        if (!strstr(al_data->user, r_filter->user)) {
            return (0);
        }
    }
    if (r_filter->files) {
        if (!al_data->filename) {
            return (0);
        }
        if (!strstr(al_data->filename, r_filter->files)) {
            return (0);
        }
    }
    return (1);
}

/* Set the proper value for the related entries */
static int _report_filter_value(const char *filter_by, int prev_filter)
{
    if (strcmp(filter_by, "group") == 0) {
        if (!(prev_filter & REPORT_REL_GROUP)) {
            prev_filter |= REPORT_REL_GROUP;
        }
        return (prev_filter);
    } else if (strcmp(filter_by, "rule") == 0) {
        if (!(prev_filter & REPORT_REL_RULE)) {
            prev_filter |= REPORT_REL_RULE;
        }
        return (prev_filter);
    } else if (strcmp(filter_by, "level") == 0) {
        if (!(prev_filter & REPORT_REL_LEVEL)) {
            prev_filter |= REPORT_REL_LEVEL;
        }
        return (prev_filter);
    } else if (strcmp(filter_by, "location") == 0) {
        if (!(prev_filter & REPORT_REL_LOCATION)) {
            prev_filter |= REPORT_REL_LOCATION;
        }
        return (prev_filter);
    } else if (strcmp(filter_by, "srcip") == 0) {
        if (!(prev_filter & REPORT_REL_SRCIP)) {
            prev_filter |= REPORT_REL_SRCIP;
        }
        return (prev_filter);
    } else if (strcmp(filter_by, "user") == 0) {
        if (!(prev_filter & REPORT_REL_USER)) {
            prev_filter |= REPORT_REL_USER;
        }
        return (prev_filter);
    } else if (strcmp(filter_by, "filename") == 0) {
        if (!(prev_filter & REPORT_REL_FILE)) {
            prev_filter |= REPORT_REL_FILE;
        }
        return (prev_filter);
    } else {
        merror("%s: ERROR: Invalid relation '%s'.", __local_name, filter_by);
        return (-1);
    }
}

/* Print related entries. The first time a value is seen is the one printed. */
static int _os_report_print_related(FILE *out, int print_related, OSList *st_data)
{
    OSListNode *list_entry;
    alert_data *saved_aldata;
    OSHash *printed;
    const char *value;
    char value_int[16];

    printed = OSHash_Create();
    if (!printed ||
            !OSHash_setSize(printed, (unsigned int)st_data->currently_size)) {
        merror(MEM_ERROR, __local_name, errno, strerror(errno));
        if (printed) {
            /* setSize() stores realloc's NULL on failure. */
            if (printed->table) {
                OSHash_Free(printed);
            } else {
                free(printed);
            }
        }
        return (0);
    }

    list_entry = OSList_GetFirstNode(st_data);
    while (list_entry) {
        saved_aldata = (alert_data *)list_entry->data;
        value = NULL;

        if (print_related & REPORT_REL_LOCATION) {
            value = saved_aldata->location;
        } else if (print_related & REPORT_REL_GROUP) {
            value = saved_aldata->group;
        } else if (print_related & REPORT_REL_RULE) {
            snprintf(value_int, sizeof(value_int), "%d", saved_aldata->rule);
            value = value_int;
        } else if (print_related & REPORT_REL_USER) {
            value = saved_aldata->user;
        } else if (print_related & REPORT_REL_SRCIP) {
            value = saved_aldata->srcip;
        } else if (print_related & REPORT_REL_LEVEL) {
            snprintf(value_int, sizeof(value_int), "%u", saved_aldata->level);
            value = value_int;
        } else if (print_related & REPORT_REL_FILE) {
            value = saved_aldata->filename;
        }

        if (value && OSHash_Add(printed, value, saved_aldata) == 2) {
            if (print_related & REPORT_REL_LOCATION) {
                l_print_out(out, "   location: '%s'", saved_aldata->location);
            } else if (print_related & REPORT_REL_GROUP) {
                l_print_out(out, "   group: '%s'", saved_aldata->group);
            } else if (print_related & REPORT_REL_RULE) {
                l_print_out(out, "   rule: '%d'", saved_aldata->rule);
            } else if ((print_related & REPORT_REL_SRCIP) && saved_aldata->srcip) {
                l_print_out(out, "   srcip: '%s'", saved_aldata->srcip);
            } else if ((print_related & REPORT_REL_USER) && saved_aldata->user) {
                l_print_out(out, "   user: '%s'", saved_aldata->user);
            } else if (print_related & REPORT_REL_LEVEL) {
                l_print_out(out, "   level: '%d'", saved_aldata->level);
            } else if ((print_related & REPORT_REL_FILE) && saved_aldata->filename) {
                l_print_out(out, "   filename: '%s'", saved_aldata->filename);
            }
        }

        list_entry = OSList_GetNextNode(st_data);
    }

    OSHash_Free(printed);
    return (0);
}

/* Add the entry to the hash. A lookup replaces the old sorted-list walk
 * (ANT-2026-AVE66YB6). */
static int _os_report_add_tostore(const char *key, OSHash *top, void *data)
{
    OSList *top_list;
    int added;

    top_list = (OSList *) OSHash_Get(top, key);
    if (top_list) {
        OSList_AddData(top_list, data);
    } else {
        top_list = OSList_Create();
        if (!top_list) {
            merror(MEM_ERROR, __local_name, errno, strerror(errno));
            return (0);
        }
        OSList_AddData(top_list, data);

        added = OSHash_Add(top, key, top_list);
        if (added != 2) {
            while (top_list->first_node) {
                OSList_DeleteOldestNode(top_list);
            }
            free(top_list);
            if (added == 0) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
            }
            return (0);
        }
    }

    return (1);
}

void os_report_printtop(FILE *out, void *tophash_pt, const char *hname, int print_related)
{
    int dopdout = 0;
    unsigned int i;
    size_t top_size = 0;
    size_t top_pos = 0;
    OSHash *tophash = (OSHash *)tophash_pt;
    OSHashNode *next_node;
    OSHashNode **top_nodes;

    if (!tophash || !tophash->table) {
        return;
    }

    for (i = 0; i <= tophash->rows; i++) {
        for (next_node = tophash->table[i]; next_node; next_node = next_node->next) {
            top_size++;
        }
    }
    if (top_size == 0) {
        return;
    }
    os_calloc(top_size, sizeof(OSHashNode *), top_nodes);
    for (i = 0; i <= tophash->rows; i++) {
        for (next_node = tophash->table[i]; next_node; next_node = next_node->next) {
            top_nodes[top_pos++] = next_node;
        }
    }
    qsort(top_nodes, top_size, sizeof(OSHashNode *), _os_report_sort_compare);

    for (top_pos = 0; top_pos < top_size; top_pos++) {
        OSList *st_data;
        char lkey[76 + 1];

        next_node = top_nodes[top_pos];
        st_data = (OSList *)next_node->data;

        /* Copy, then mark a key longer than the column. The stored key
         * stays intact; the old code truncated it in place. */
        if (snprintf(lkey, sizeof(lkey), "%s", next_node->key) > 76) {
            lkey[74] = '.';
            lkey[75] = '.';
        }

        if (!print_related) {
            if (!dopdout) {
                _os_header_print(out, print_related, hname);
                dopdout = 1;
            }
            l_print_out(out, "%-78s|%-8d|", lkey, st_data->currently_size);
        } else {
            if (!dopdout) {
                _os_header_print(out, print_related, hname);
                dopdout = 1;
            }
            l_print_out(out, "%-78s|%-8d|", lkey, st_data->currently_size);

            if (print_related & REPORT_REL_LOCATION) {
                _os_report_print_related(out, REPORT_REL_LOCATION, st_data);
            }
            if (print_related & REPORT_REL_SRCIP) {
                _os_report_print_related(out, REPORT_REL_SRCIP, st_data);
            }
            if (print_related & REPORT_REL_USER) {
                _os_report_print_related(out, REPORT_REL_USER, st_data);
            }
            if (print_related & REPORT_REL_RULE) {
                _os_report_print_related(out, REPORT_REL_RULE, st_data);
            }
            if (print_related & REPORT_REL_GROUP) {
                _os_report_print_related(out, REPORT_REL_GROUP, st_data);
            }
            if (print_related & REPORT_REL_LEVEL) {
                _os_report_print_related(out, REPORT_REL_LEVEL, st_data);
            }
            if (print_related & REPORT_REL_FILE) {
                _os_report_print_related(out, REPORT_REL_FILE, st_data);
            }
        }
    }

    free(top_nodes);

    if (dopdout == 1) {
        l_print_out(out, " ");
        l_print_out(out, " ");
    }
    return;
}

/* Free the hash and the per-key lists. OSHash_Free() does not free data. */
static void _os_report_free_store(OSHash *top)
{
    unsigned int i;
    OSHashNode *curr_node;
    OSList *top_list;

    if (!top->table) {
        free(top);
        return;
    }

    for (i = 0; i <= top->rows; i++) {
        for (curr_node = top->table[i]; curr_node; curr_node = curr_node->next) {
            top_list = (OSList *)curr_node->data;
            if (!top_list) {
                continue;
            }
            while (top_list->first_node) {
                OSList_DeleteOldestNode(top_list);
            }
            free(top_list);
            curr_node->data = NULL;
        }
    }

    OSHash_Free(top);
}

static void _os_report_free_stores(report_filter *r_filter)
{
    if (!r_filter) {
        return;
    }

    if (r_filter->top_user) {
        _os_report_free_store(r_filter->top_user);
        r_filter->top_user = NULL;
    }
    if (r_filter->top_srcip) {
        _os_report_free_store(r_filter->top_srcip);
        r_filter->top_srcip = NULL;
    }
    if (r_filter->top_level) {
        _os_report_free_store(r_filter->top_level);
        r_filter->top_level = NULL;
    }
    if (r_filter->top_rule) {
        _os_report_free_store(r_filter->top_rule);
        r_filter->top_rule = NULL;
    }
    if (r_filter->top_group) {
        _os_report_free_store(r_filter->top_group);
        r_filter->top_group = NULL;
    }
    if (r_filter->top_location) {
        _os_report_free_store(r_filter->top_location);
        r_filter->top_location = NULL;
    }
    if (r_filter->top_files) {
        _os_report_free_store(r_filter->top_files);
        r_filter->top_files = NULL;
    }
}

void os_ReportdStart(report_filter *r_filter)
{
    int alerts_processed = 0;
    int alerts_filtered = 0;
    int data_size = 0;
    int i;
    char *first_alert = NULL;
    char *last_alert = NULL;
    alert_data **data_to_clean = NULL;
    FILE *out;

    time_t tm;
    struct tm tm_buf;
    struct tm *p;

    file_queue *fileq;
    alert_data *al_data;

    out = r_filter->fp;

    /* Get current time before starting */
    tm = time(NULL);
    localtime_r(&tm, &tm_buf);
    p = &tm_buf;

    /* Initiate file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);

    if (r_filter->report_type == REPORT_TYPE_DAILY && r_filter->filename) {
        fileq->fp = fopen(r_filter->filename, "r");
        if (!fileq->fp) {
            merror("%s: ERROR: Unable to open alerts file to generate report.", __local_name);
            goto cleanup;
        }
    } else {
        fileq->fp = stdin;
    }

    /* Create top hashes. Sized to the kept alerts after the file is read. */
    r_filter->top_user = OSHash_Create();
    r_filter->top_srcip = OSHash_Create();
    r_filter->top_level = OSHash_Create();
    r_filter->top_rule = OSHash_Create();
    r_filter->top_group = OSHash_Create();
    r_filter->top_location = OSHash_Create();
    r_filter->top_files = OSHash_Create();

    if (!r_filter->top_user || !r_filter->top_srcip || !r_filter->top_level || !r_filter->top_rule
            || !r_filter->top_group || !r_filter->top_location || !r_filter->top_files) {
        merror(MEM_ERROR, __local_name, errno, strerror((errno)));
        goto cleanup;
    }



    Init_FileQueue(fileq, p, CRALERT_READ_ALL | CRALERT_FP_SET);

    /* Read the alerts */
    while (1) {
        /* Get message if available */
        al_data = Read_FileMon(fileq, p, 1);
        if (!al_data) {
            break;
        }

        alerts_processed++;

        /* Check the filters */
        if (!_os_report_check_filters(al_data, r_filter)) {
            FreeAlertData(al_data);
            continue;
        }

        /* Keep the alert. Grow geometrically: os_AddPtArray() recounts
         * the whole array on every append (ANT-2026-AVE66YB6). */
        if (alerts_filtered + 2 > data_size) {
            data_size = data_size ? data_size * 2 : 1024;
            os_realloc(data_to_clean, (size_t)data_size * sizeof(alert_data *),
                       data_to_clean);
        }
        data_to_clean[alerts_filtered++] = al_data;
        data_to_clean[alerts_filtered] = NULL;
    }

    if (alerts_filtered > 0 &&
            (!OSHash_setSize(r_filter->top_user, (unsigned int)alerts_filtered) ||
             !OSHash_setSize(r_filter->top_srcip, (unsigned int)alerts_filtered) ||
             !OSHash_setSize(r_filter->top_level, (unsigned int)alerts_filtered) ||
             !OSHash_setSize(r_filter->top_rule, (unsigned int)alerts_filtered) ||
             !OSHash_setSize(r_filter->top_group, (unsigned int)alerts_filtered) ||
             !OSHash_setSize(r_filter->top_location, (unsigned int)alerts_filtered) ||
             !OSHash_setSize(r_filter->top_files, (unsigned int)alerts_filtered))) {
        merror(MEM_ERROR, __local_name, errno, strerror(errno));
        goto cleanup;
    }

    for (i = 0; i < alerts_filtered; i++) {
        al_data = data_to_clean[i];

        /* Set first and last alert for summary */
        if (!first_alert) {
            first_alert = al_data->date;
        }
        last_alert = al_data->date;

        /* Add source IP if it is set properly */
        if (al_data->srcip != NULL && strcmp(al_data->srcip, "(none)") != 0) {
            _os_report_add_tostore(al_data->srcip, r_filter->top_srcip, al_data);
        }

        /* Add user if it is set properly */
        if (al_data->user != NULL && strcmp(al_data->user, "(none)") != 0) {
            _os_report_add_tostore(al_data->user, r_filter->top_user, al_data);
        }

        /* Add level and severity */
        {
            char mlevel[16];
            char mrule[76 + 1];
            mrule[76] = '\0';
            snprintf(mlevel, 16, "Severity %d" , al_data->level);
            snprintf(mrule, 76, "%d - %s" , al_data->rule, al_data->comment);

            _os_report_add_tostore(mlevel, r_filter->top_level,
                                   al_data);
            _os_report_add_tostore(mrule, r_filter->top_rule,
                                   al_data);
        }

        /* Deal with the group */
        {
            char *tmp_str;
            char **mgroup;
            char **mgroup_orig;

            mgroup = al_data->group ? OS_StrBreak(',', al_data->group, 32)
                                    : NULL;
            mgroup_orig = mgroup;
            if (mgroup) {
                while (*mgroup) {
                    tmp_str = *mgroup;
                    while (*tmp_str == ' ') {
                        tmp_str++;
                    }
                    if (*tmp_str == '\0') {
                        free(*mgroup);
                        mgroup++;
                        continue;
                    }

                    _os_report_add_tostore(tmp_str, r_filter->top_group,
                                           al_data);

                    free(*mgroup);
                    mgroup++;
                }
                free(mgroup_orig);
            } else if (al_data->group) {
                tmp_str = al_data->group;
                while (*tmp_str == ' ') {
                    tmp_str++;
                }
                if (*tmp_str != '\0') {
                    _os_report_add_tostore(tmp_str, r_filter->top_group,
                                           al_data);
                }
            }
        }

        /* Add to the location top filter */
        _os_report_add_tostore(al_data->location, r_filter->top_location,
                               al_data);

        if (al_data->filename != NULL) {
            _os_report_add_tostore(al_data->filename, r_filter->top_files,
                                   al_data);
        }
    }



    /* No report available */
    if (alerts_filtered == 0) {
        if (!r_filter->report_name) {
            merror("%s: INFO: Report completed and zero alerts post-filter.", __local_name);
        } else {
            merror("%s: INFO: Report '%s' completed and zero alerts post-filter.", __local_name, r_filter->report_name);
        }

        goto cleanup;
    }

    if (r_filter->report_name) {
        verbose("%s: INFO: Report '%s' completed. Creating output...", __local_name, r_filter->report_name);
    } else {
        verbose("%s: INFO: Report completed. Creating output...", __local_name);
    }

    l_print_out(out, " ");
    if (r_filter->report_name) {
        l_print_out(out, "Report '%s' completed.", r_filter->report_name);
    } else {
        l_print_out(out, "Report completed. ==");
    }
    l_print_out(out, "------------------------------------------------");

    l_print_out(out, "->Processed alerts: %d", alerts_processed);
    l_print_out(out, "->Post-filtering alerts: %d", alerts_filtered);
    l_print_out(out, "->First alert: %s", first_alert);
    l_print_out(out, "->Last alert: %s", last_alert);
    l_print_out(out, " ");
    l_print_out(out, " ");

    os_report_printtop(out, r_filter->top_srcip, "Source ip", 0);
    os_report_printtop(out, r_filter->top_user, "Username", 0);
    os_report_printtop(out, r_filter->top_level, "Level", 0);
    os_report_printtop(out, r_filter->top_group, "Group", 0);
    os_report_printtop(out, r_filter->top_location, "Location", 0);
    os_report_printtop(out, r_filter->top_rule, "Rule", 0);
    os_report_printtop(out, r_filter->top_files, "Filenames", 0);

    /* Print related events */
    if (r_filter->related_srcip)
        os_report_printtop(out, r_filter->top_srcip, "Source ip",
                           r_filter->related_srcip);

    if (r_filter->related_user)
        os_report_printtop(out, r_filter->top_user, "Username",
                           r_filter->related_user);

    if (r_filter->related_level)
        os_report_printtop(out, r_filter->top_level, "Level",
                           r_filter->related_level);

    if (r_filter->related_group)
        os_report_printtop(out, r_filter->top_group, "Group",
                           r_filter->related_group);

    if (r_filter->related_location)
        os_report_printtop(out, r_filter->top_location, "Location",
                           r_filter->related_location);

    if (r_filter->related_rule)
        os_report_printtop(out, r_filter->top_rule, "Rule",
                           r_filter->related_rule);

    if (r_filter->related_file)
        os_report_printtop(out, r_filter->top_files, "Filename",
                           r_filter->related_file);

    /* If we have to dump the alerts */
    if (data_to_clean) {
        i = 0;

        if (r_filter->show_alerts) {
            l_print_out(out, "Log dump:");
            l_print_out(out, "------------------------------------------------");
        }
        while (data_to_clean[i]) {
            alert_data *md = data_to_clean[i];
            if (r_filter->show_alerts) {
                l_print_out(out, "%s %s\nRule: %d (level %d) -> '%s'\n%s\n\n", md->date, md->location, md->rule, md->level, md->comment, md->log[0]);
            }
            FreeAlertData(md);
            i++;
        }
        free(data_to_clean);
        data_to_clean = NULL;
    }

    cleanup:
    if (data_to_clean) {
        int j = 0;

        while (data_to_clean[j]) {
            FreeAlertData(data_to_clean[j]);
            j++;
        }
        free(data_to_clean);
        data_to_clean = NULL;
    }
    _os_report_free_stores(r_filter);

    if (fileq->fp && fileq->fp != stdin) {
        fclose(fileq->fp);
    }

    free(fileq);
}

/* Check the configuration filters */
int os_report_configfilter(const char *filter_by, const char *filter_value,
                           report_filter *r_filter, int arg_type)
{
    if (!filter_by || !filter_value) {
        return (-1);
    }

    if (arg_type == REPORT_FILTER) {
        if (strcmp(filter_by, "group") == 0) {
            r_filter->group = filter_value;
        } else if (strcmp(filter_by, "rule") == 0) {
            r_filter->rule = filter_value;
        } else if (strcmp(filter_by, "level") == 0) {
            r_filter->level = filter_value;
        } else if (strcmp(filter_by, "location") == 0) {
            r_filter->location = filter_value;
        } else if (strcmp(filter_by, "user") == 0) {
            r_filter->user = filter_value;
        } else if (strcmp(filter_by, "srcip") == 0) {
            r_filter->srcip = filter_value;
        } else if (strcmp(filter_by, "filename") == 0) {
            r_filter->files = filter_value;
        } else {
            merror("%s: ERROR: Invalid filter '%s'.", __local_name, filter_by);
            return (-1);
        }
    } else {
        if (strcmp(filter_by, "group") == 0) {
            r_filter->related_group =
                _report_filter_value(filter_value, r_filter->related_group);

            if (r_filter->related_group == -1) {
                return (-1);
            }
        } else if (strcmp(filter_by, "rule") == 0) {
            r_filter->related_rule =
                _report_filter_value(filter_value, r_filter->related_rule);

            if (r_filter->related_rule == -1) {
                return (-1);
            }
        } else if (strcmp(filter_by, "level") == 0) {
            r_filter->related_level =
                _report_filter_value(filter_value, r_filter->related_level);

            if (r_filter->related_level == -1) {
                return (-1);
            }
        } else if (strcmp(filter_by, "location") == 0) {
            r_filter->related_location =
                _report_filter_value(filter_value, r_filter->related_location);

            if (r_filter->related_location == -1) {
                return (-1);
            }
        } else if (strcmp(filter_by, "srcip") == 0) {
            r_filter->related_srcip =
                _report_filter_value(filter_value, r_filter->related_srcip);

            if (r_filter->related_srcip == -1) {
                return (-1);
            }
        } else if (strcmp(filter_by, "user") == 0) {
            r_filter->related_user =
                _report_filter_value(filter_value, r_filter->related_user);

            if (r_filter->related_user == -1) {
                return (-1);
            }
        } else if (strcmp(filter_by, "filename") == 0) {
            r_filter->related_file =
                _report_filter_value(filter_value, r_filter->related_file);

            if (r_filter->related_file == -1) {
                return (-1);
            }
        } else {
            merror("%s: ERROR: Invalid related entry '%s'.", __local_name, filter_by);
            return (-1);
        }
    }

    return (0);
}

