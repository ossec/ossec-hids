/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

/* Max lines (or fgets-sized chunks) one reader may take per visit.
 * 0 means unlimited (legacy behaviour). */
int max_lines = 0;

/* Lines the reader that has its turn took so far. */
static int lines_read;

/* Set when logr_fgets/logr_consume_line stop for the budget, not EOF. */
static int budget_hit;

void logr_begin_read(void)
{
    lines_read = 0;
    budget_hit = 0;
}

int logr_budget_exhausted(void)
{
    return (budget_hit);
}

/* True if another line/chunk may be taken this visit. drop_it skips are
 * unlimited so old content can be drained in one go. */
int logr_consume_line(int drop_it)
{
    if (!drop_it && max_lines && lines_read++ >= max_lines) {
        budget_hit = 1;
        return 0;
    }
    return 1;
}

/* fgets_no_nul() with the per-visit line budget. */
char *logr_fgets(char *str, int size, int pos, int drop_it)
{
    if (!logr_consume_line(drop_it)) {
        return (NULL);
    }
    return (fgets_no_nul(str, size, logff[pos].fp));
}

/* Discard through the next newline, counting against the same budget. */
int logr_fdrain_to_newline(int pos, int drop_it)
{
    char buf[OS_MAXSTR + 1];

    buf[OS_MAXSTR] = '\0';
    while (logr_fgets(buf, OS_MAXSTR - OS_LOG_HEADER, pos, drop_it) != NULL) {
        if (strchr(buf, '\n') != NULL) {
            return (1);
        }
    }
    return (0);
}
