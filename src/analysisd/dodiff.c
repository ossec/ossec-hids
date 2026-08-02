/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dodiff.h"

#include "shared.h"
#include "eventinfo.h"

#ifndef WIN32
static pthread_mutex_t do_diff_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static int _add2last(const char *str, size_t strsize, const char *file)
{
    FILE *fp;

    fp = fopen(file, "w");
    if (!fp) {
        /* Try to create the directories */
        char *dirrule = NULL;
        char *diragent = NULL;

        dirrule = strrchr(file, '/');
        if (!dirrule) {
            merror("%s: ERROR: Invalid file name to diff: %s",
                   ARGV0, file);
            return (0);
        }
        *dirrule = '\0';

        diragent = strrchr(file, '/');
        if (!diragent) {
            merror("%s: ERROR: Invalid file name to diff (2): %s",
                   ARGV0, file);
            return (0);
        }
        *diragent = '\0';

        /* Check if the diragent exists */
        if (IsDir(file) != 0) {
            if (mkdir(file, 0770) == -1) {
                merror(MKDIR_ERROR, ARGV0, file, errno, strerror(errno));
                return (0);
            }
        }
        *diragent = '/';

        if (IsDir(file) != 0) {
            if (mkdir(file, 0770) == -1) {
                merror(MKDIR_ERROR, ARGV0, file, errno, strerror(errno));
                return (0);
            }
        }
        *dirrule = '/';

        fp = fopen(file, "w");
        if (!fp) {
            merror(FOPEN_ERROR, ARGV0, file, errno, strerror(errno));
            return (0);
        }
    }

    fwrite(str, strsize + 1, 1, fp);
    fclose(fp);
    return (1);
}

int doDiff(RuleInfo *rule, const Eventinfo *lf)
{
    time_t date_of_change;
    char *htpt = NULL;
    char flastfile[OS_SIZE_2048 + 1];
    char flastcontent[OS_SIZE_8192 + 1];
    int result = 0;

#ifndef WIN32
    os_mutex_lock(&do_diff_mutex);
    os_mutex_lock(&rule->mutex);
#endif

    /* Clean up global */
    flastcontent[0] = '\0';
    flastcontent[OS_SIZE_8192] = '\0';
    OS_FreeRuleLastEvents(rule);

    if (lf->hostname[0] == '(') {
        htpt = strchr(lf->hostname, ')');
        if (htpt) {
            *htpt = '\0';
        }
        snprintf(flastfile, OS_SIZE_2048, "%s/%s/%d/%s", DIFF_DIR, lf->hostname + 1,
                 rule->sigid, DIFF_LAST_FILE);

        if (htpt) {
            *htpt = ')';
        }
        htpt = NULL;
    } else {
        snprintf(flastfile, OS_SIZE_2048, "%s/%s/%d/%s", DIFF_DIR, lf->hostname,
                 rule->sigid, DIFF_LAST_FILE);
    }

    /* lf->size can't be too long */
    if (lf->size >= OS_SIZE_8192) {
        merror("%s: ERROR: event size (%ld) too long for diff.", ARGV0, lf->size);
        goto out;
    }

    /* Check if last diff exists */
    date_of_change = File_DateofChange(flastfile);
    if (date_of_change <= 0) {
        if (!_add2last(lf->log, lf->size, flastfile)) {
            merror("%s: ERROR: unable to create last file: %s", ARGV0, flastfile);
        }
        goto out;
    } else {
        FILE *fp;
        size_t n;
        fp = fopen(flastfile, "r");
        if (!fp) {
            merror(FOPEN_ERROR, ARGV0, flastfile, errno, strerror(errno));
            goto out;
        }

        n = fread(flastcontent, 1, OS_SIZE_8192, fp);
        if (n > 0) {
            flastcontent[n] = '\0';
        } else {
            merror("%s: ERROR: read error on %s", ARGV0, flastfile);
            fclose(fp);
            goto out;
        }
        fclose(fp);
    }

    /* Nothing changed */
    if (strcmp(flastcontent, lf->log) == 0) {
        goto out;
    }

    if (!_add2last(lf->log, lf->size, flastfile)) {
        merror("%s: ERROR: unable to create last file: %s", ARGV0, flastfile);
    }

    /* Heap-copy last_events then move onto the firing event under the same lock. */
    OS_SetRuleLastEvent(rule, 0, "Previous output:");
    OS_SetRuleLastEvent(rule, 1, flastcontent);
    OS_MoveRuleLastEvents(rule, (Eventinfo *)lf);
    result = 1;

out:
#ifndef WIN32
    os_mutex_unlock(&rule->mutex);
    os_mutex_unlock(&do_diff_mutex);
#endif
    return result;
}

