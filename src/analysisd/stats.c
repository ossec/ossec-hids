/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "analysisd.h"
#include "stats.h"
#include "rules.h"
#include "error_messages/error_messages.h"
#include "headers/file_op.h"
#include "alerts/alerts.h"
#include "headers/debug_op.h"

/* Global definition */
char __stats_comment[192];

static const char *(weekdays[]) = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
                      "Friday", "Saturday"
                     };

static const char *(l_month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                     "Sep", "Oct", "Nov", "Dec"
                    };

/* Global variables */

/* Hour 25 is internally used */
static int _RWHour[7][25];
static int _CWHour[7][25];

static int _RHour[25];
static int _CHour[25];

static int _cignorehour = 0;
static int _fired = 0;
#ifndef WIN32
static pthread_mutex_t stats_hour_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static int _daily_errors = 0;
static int maxdiff = 0;
static int mindiff = 0;
static int percent_diff = 20;

/* Last msgs flood window. TLS so each process/match shard owns private state
 * (LastMsg runs only on the analyze path; one process thread owns each shard). */
static __thread char *_lastmsg;
static __thread char *_prevlast;
static __thread char *_pprevlast;

static void lastmsg_ensure_init(void)
{
    if (_lastmsg) {
        return;
    }
    os_strdup(" ", _lastmsg);
    os_strdup(" ", _prevlast);
    os_strdup(" ", _pprevlast);
}


static void print_totals(void)
{
    int i, totals = 0;
    char logfile[OS_FLSIZE + 1];
    FILE *flog;

    /* Create the path for the logs */
    snprintf(logfile, OS_FLSIZE, "%s/%d/", STATSAVED, prev_year);
    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, ARGV0, logfile, errno, strerror(errno));
            return;
        }

    snprintf(logfile, OS_FLSIZE, "%s/%d/%s", STATSAVED, prev_year, prev_month);

    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, ARGV0, logfile, errno, strerror(errno));
            return;
        }

    /* Create the logfile name */
    snprintf(logfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             STATSAVED,
             prev_year,
             prev_month,
             "totals",
             today);

    flog = fopen(logfile, "a");
    if (!flog) {
        merror(FOPEN_ERROR, ARGV0, logfile, errno, strerror(errno));
        return;
    }

    /* Print the hourly stats */
    for (i = 0; i <= 23; i++) {
        fprintf(flog, "Hour totals - %d:%d\n", i, _CHour[i]);
        totals += _CHour[i];
    }
    fprintf(flog, "Total events for day:%d\n", totals);

    fclose(flog);
}

/* Return the parameter (event_number + 20 % of it)
 * If event_number < mindiff, return mindiff
 * If event_number > maxdiff, return maxdiff
 */
static int gethour(int event_number)
{
    int event_diff;

    event_diff = (event_number * percent_diff) / 100;
    event_diff++;

    if (event_diff < mindiff) {
        return (event_number + mindiff);
    } else if (event_diff > maxdiff) {
        return (event_number + maxdiff);
    }

    return (event_number + event_diff);
}

/* Update_Hour: done daily */
void Update_Hour()
{
    int i, j;
    int inter;

    /* Print total number of logs received per hour */
    print_totals();

    /* Hourly update */
    _RHour[24]++;
    inter = _RHour[24];
    if (inter > 7) {
        inter = 7;
    }

    for (i = 0; i <= 24; i++) {
        char _hourly[128]; /* _hourly file */

        FILE *fp;

        if (i != 24) {
            /* If saved hourly = 0, just copy the current hourly rate */
            if (_CHour[i] == 0) {
                continue;
            }

            if (_RHour[i] == 0) {
                _RHour[i] = _CHour[i] + 20;
            }

            else {
                /* If we had too many errors this day */
                if (_daily_errors >= 3) {
                    _RHour[i] = (((3 * _CHour[i]) + (inter * _RHour[i])) / (inter + 3)) + 25;
                }

                else {
                    /* The average is going to be the number of interactions +
                     * the current hourly rate, divided by 4 */
                    _RHour[i] = ((_CHour[i] + (inter * _RHour[i])) / (inter + 1)) + 5;
                }
            }
        }

        snprintf(_hourly, 128, "%s/%d", STATQUEUE, i);
        fp = fopen(_hourly, "w");
        if (fp) {
            fprintf(fp, "%d", _RHour[i]);
            fclose(fp);
        }

        else {
            merror(FOPEN_ERROR, "logstats", _hourly, errno, strerror(errno));
        }

        _CHour[i] = 0; /* Zero the current hour */
    }

    /* Weekly */
    for (i = 0; i <= 6; i++) {
        char _weekly[128];
        FILE *fp;

        _CWHour[i][24]++;
        inter = _CWHour[i][24];
        if (inter > 7) {
            inter = 7;
        }

        for (j = 0; j <= 24; j++) {
            if (j != 24) {
                if (_CWHour[i][j] == 0) {
                    continue;
                }

                if (_RWHour[i][j] == 0) {
                    _RWHour[i][j] = _CWHour[i][j] + 20;
                }

                else {
                    if (_daily_errors >= 3) {
                        _RWHour[i][j] = (((3 * _CWHour[i][j]) + (inter * _RWHour[i][j])) / (inter + 3)) + 25;
                    } else {
                        _RWHour[i][j] = ((_CWHour[i][j] + (inter * _RWHour[i][j])) / (inter + 1)) + 5;
                    }
                }
            }

            snprintf(_weekly, 128, "%s/%d/%d", STATWQUEUE, i, j);
            fp = fopen(_weekly, "w");
            if (fp) {
                fprintf(fp, "%d", _RWHour[i][j]);
                fclose(fp);
            } else {
                merror(FOPEN_ERROR, "logstats", _weekly, errno, strerror(errno));
            }

            _CWHour[i][j] = 0;
        }
    }

    _daily_errors = 0;
    return;
}

/* Check Hourly stats */
int Check_Hour(char *comment_out, size_t comment_sz)
{
    int result = 0;
    int hour;
    int wday;

    hour = __crt_hour;
    wday = __crt_wday;

    if (hour < 0 || hour > 23 || wday < 0 || wday > 6) {
        return 0;
    }

#ifndef WIN32
    os_mutex_lock(&stats_hour_mutex);
#endif
    _CHour[hour]++;
    _CWHour[wday][hour]++;

    if (_RHour[24] <= 2) {
        goto out;
    }

    /* Checking if any message was already fired for this hour */
    if ((_daily_errors >= 3) || ((_fired == 1) && (_cignorehour == hour))) {
        goto out;
    }

    else if (_cignorehour != hour) {
        _cignorehour = hour;
        _fired = 0;
    }

    /* Check if passed the threshold */
    if (_RHour[hour] != 0) {
        if (_CHour[hour] > (_RHour[hour])) {
            if (_CHour[hour] > (gethour(_RHour[hour]))) {
                /* snprintf will null terminate */
                snprintf(__stats_comment, 191,
                         "The average number of logs"
                         " between %d:00 and %d:00 is %d. We "
                         "reached %d.", hour, hour + 1,
                         _RHour[hour], _CHour[hour]);


                _fired = 1;
                _daily_errors++;
                result = 1;
                goto out;
            }
        }
    }

    /* We need to have at least 3 days of stats */
    if (_RWHour[wday][24] <= 2) {
        goto out;
    }

    /* Check for the hour during a specific day of the week */
    if (_RWHour[wday][hour] != 0) {
        if (_CWHour[wday][hour] > _RWHour[wday][hour]) {
            if (_CWHour[wday][hour] >
                    gethour(_RWHour[wday][hour])) {
                snprintf(__stats_comment, 191,
                         "The average number of logs"
                         " between %d:00 and %d:00 on %s is %d. We"
                         " reached %d.", hour, hour + 1,
                         weekdays[wday],
                         _RWHour[wday][hour],
                         _CWHour[wday][hour]);


                _fired = 1;
                _daily_errors++;
                result = 1;
                goto out;
            }
        }
    }

out:
    if (result && comment_out && comment_sz > 0) {
        snprintf(comment_out, comment_sz, "%s", __stats_comment);
    }
#ifndef WIN32
    os_mutex_unlock(&stats_hour_mutex);
#endif
    return result;
}

/* Start hourly stats and other necessary variables */
int Start_Hour()
{
    int i = 0, j = 0;
    struct tm *p;

    /* Current time */
    p = localtime(&c_time);

    /* Other global variables */
    _fired = 0;
    _cignorehour = 0;

    today = p->tm_mday;
    thishour = p->tm_hour;
    prev_year = p->tm_year + 1900;
    strncpy(prev_month, l_month[p->tm_mon], 3);
    prev_month[3] = '\0';

    /* Clear some memory */
    memset(__stats_comment, '\0', 192);

    /* Get maximum/minimum diffs */
    maxdiff = getDefine_Int("analysisd",
                            "stats_maxdiff",
                            10, 999999);

    mindiff = getDefine_Int("analysisd",
                            "stats_mindiff",
                            10, 999999);

    percent_diff = getDefine_Int("analysisd",
                                 "stats_percent_diff",
                                 5, 9999);

    /* Last three messages — TLS; init this thread (main/startup). */
    lastmsg_ensure_init();

    /* Create the stat queue directories */
    if (IsDir(STATWQUEUE) == -1) {
        if (mkdir(STATWQUEUE, 0770) == -1) {
            merror("%s: logstat: Unable to create stat queue: %s",
                   ARGV0, STATWQUEUE);
            return (-1);
        }
    }

    if (IsDir(STATQUEUE) == -1) {
        if (mkdir(STATQUEUE, 0770) == -1) {
            merror("%s: logstat: Unable to create stat queue: %s",
                   ARGV0, STATQUEUE);
            return (-1);
        }
    }

    /* Create store dir */
    if (IsDir(STATSAVED) == -1) {
        if (mkdir(STATSAVED, 0770) == -1) {
            merror("%s: logstat: Unable to create stat directory: %s",
                   ARGV0, STATSAVED);
            return (-1);
        }
    }

    /* Create hourly directory (24 hour is the stats) */
    for (i = 0; i <= 24; i++) {
        char _hourly[128];
        snprintf(_hourly, 128, "%s/%d", STATQUEUE, i);

        _CHour[i] = 0;
        if (File_DateofChange(_hourly) < 0) {
            _RHour[i] = 0;
        }

        else {
            FILE *fp;
            fp = fopen(_hourly, "r");
            if (!fp) {
                _RHour[i] = 0;
            } else {
                if (fscanf(fp, "%d", &_RHour[i]) <= 0) {
                    _RHour[i] = 0;
                }

                if (_RHour[i] < 0) {
                    _RHour[i] = 0;
                }
                fclose(fp);
            }
        }
    }

    /* Create weekly/hourly directories */
    for (i = 0; i <= 6; i++) {
        char _weekly[128];
        snprintf(_weekly, 128, "%s/%d", STATWQUEUE, i);
        if (IsDir(_weekly) == -1)
            if (mkdir(_weekly, 0770) == -1) {
                merror("%s: logstat: Unable to create stat queue: %s",
                       ARGV0, _weekly);
                return (-1);
            }

        for (j = 0; j <= 24; j++) {
            _CWHour[i][j] = 0;
            snprintf(_weekly, 128, "%s/%d/%d", STATWQUEUE, i, j);
            if (File_DateofChange(_weekly) < 0) {
                _RWHour[i][j] = 0;
            } else {
                FILE *fp;
                fp = fopen(_weekly, "r");
                if (!fp) {
                    _RWHour[i][j] = 0;
                } else {
                    if (fscanf(fp, "%d", &_RWHour[i][j]) <= 0) {
                        _RWHour[i][j] = 0;
                    }

                    if (_RWHour[i][j] < 0) {
                        _RWHour[i][j] = 0;
                    }
                    fclose(fp);
                }
            }
        }
    }
    return (0);
}

/* Check if the message received is repeated to avoid
 * floods of the same message
 */
int LastMsg_Stats(const char *log)
{
    lastmsg_ensure_init();

    if (strcmp(log, _lastmsg) == 0) {
        return 1;
    }
    if (strcmp(log, _prevlast) == 0) {
        return 1;
    }
    if (strcmp(log, _pprevlast) == 0) {
        return 1;
    }
    return 0;
}

/* If the message is not repeated, rearrange the last
 * received messages
 */
void LastMsg_Change(const char *log)
{
    lastmsg_ensure_init();

    free(_pprevlast);
    _pprevlast = _prevlast;
    _prevlast = _lastmsg;
    os_strdup(log, _lastmsg);
}

