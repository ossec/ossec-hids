/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

static const char *(months[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                };

/* Live daemon log. Each writer fopen/fclose's it, so rename starts a new file. */
#define OSSEC_LOG_LIVE "/logs/ossec.log"
#define OSSEC_LOG_DIR  "/logs/ossec"

static int mond_ensure_dir(const char *path)
{
    if (IsDir(path) == 0) {
        return (0);
    }
    if (mkdir(path, 0770) == 0 || (errno == EEXIST && IsDir(path) == 0)) {
        return (0);
    }
    merror(MKDIR_ERROR, ARGV0, path, errno, strerror(errno));
    return (-1);
}

static void mond_ossec_log_path(char *dst, int year, int mon, int day)
{
    snprintf(dst, OS_FLSIZE, OSSEC_LOG_DIR "/%d/%s/ossec-%02d.log",
             year, months[mon], day);
}

/* Move the live ossec.log into the dated tree, then sign and compress it
 * with the same flags as the alert logs (#704). */
static void rotate_ossec_log(int cday, int cmon, int cyear, const struct tm *prev)
{
    char dated[OS_FLSIZE + 1];
    char dated_old[OS_FLSIZE + 1];
    char dir_year[OS_FLSIZE + 1];
    char dir_mon[OS_FLSIZE + 1];
    FILE *fp;
    mode_t old_umask;

    if (File_DateofChange(OSSEC_LOG_LIVE) < 0) {
        return;
    }

    if (mond_ensure_dir(OSSEC_LOG_DIR) < 0) {
        return;
    }

    snprintf(dir_year, OS_FLSIZE, OSSEC_LOG_DIR "/%d", cyear);
    if (mond_ensure_dir(dir_year) < 0) {
        return;
    }

    snprintf(dir_mon, OS_FLSIZE, OSSEC_LOG_DIR "/%d/%s", cyear, months[cmon]);
    if (mond_ensure_dir(dir_mon) < 0) {
        return;
    }

    memset(dated, '\0', OS_FLSIZE + 1);
    memset(dated_old, '\0', OS_FLSIZE + 1);
    mond_ossec_log_path(dated, cyear, cmon, cday);

    if (rename(OSSEC_LOG_LIVE, dated) < 0) {
        merror("%s: ERROR: Could not rotate '%s' to '%s': %s",
               ARGV0, OSSEC_LOG_LIVE, dated, strerror(errno));
        return;
    }

    /* Recreate the live file as ossec:ossec 0660 before the next writer. */
    old_umask = umask(0117);
    fp = fopen(OSSEC_LOG_LIVE, "a");
    umask(old_umask);
    if (fp) {
        fclose(fp);
    } else {
        merror(FOPEN_ERROR, ARGV0, OSSEC_LOG_LIVE, errno, strerror(errno));
    }

    mond_ossec_log_path(dated_old, prev->tm_year + 1900, prev->tm_mon, prev->tm_mday);
    OS_SignLog(dated, dated_old, 0);
    OS_CompressLog(dated);
}


void manage_files(int cday, int cmon, int cyear)
{
    time_t tm_old;
    struct tm *pp_old;

#ifndef SOLARIS
    struct tm p_old;
#endif

    char elogfile[OS_FLSIZE + 1];
    char elogfile_old[OS_FLSIZE + 1];

    char alogfile[OS_FLSIZE + 1];
    char alogfile_old[OS_FLSIZE + 1];

    char ajlogfile[OS_FLSIZE + 1];
    char ajlogfile_old[OS_FLSIZE + 1];

    char flogfile[OS_FLSIZE + 1];
    char flogfile_old[OS_FLSIZE + 1];
    
    char ejlogfile[OS_FLSIZE + 1];
    char ejlogfile_old[OS_FLSIZE + 1];

    /* Get time from the day before (for log signing) */
    tm_old = time(NULL);
    tm_old -= 93500;
#ifndef SOLARIS
    pp_old = localtime_r(&tm_old, &p_old);
#else
    pp_old = localtime(&tm_old);
#endif

    memset(elogfile, '\0', OS_FLSIZE + 1);
    memset(elogfile_old, '\0', OS_FLSIZE + 1);
    memset(alogfile, '\0', OS_FLSIZE + 1);
    memset(alogfile_old, '\0', OS_FLSIZE + 1);
    memset(ajlogfile, '\0', OS_FLSIZE + 1);
    memset(ajlogfile_old, '\0', OS_FLSIZE + 1);
    memset(flogfile, '\0', OS_FLSIZE + 1);
    memset(flogfile_old, '\0', OS_FLSIZE + 1);
    memset(ejlogfile, '\0', OS_FLSIZE + 1);
    memset(ejlogfile_old, '\0', OS_FLSIZE + 1);
    /* When the day changes, we wait up to day_wait before compressing the file */
    sleep(mond.day_wait);

    /* Event logfile */
    snprintf(elogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             EVENTS,
             cyear,
             months[cmon],
             "archive",
             cday);
    /* Event log file old */
    snprintf(elogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             EVENTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "archive",
             pp_old->tm_mday);
    OS_SignLog(elogfile, elogfile_old, 0);
    OS_CompressLog(elogfile);

    /* JSON Event logfile */
    snprintf(ejlogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
             EVENTS,
             cyear,
             months[cmon],
             "archive",
             cday);
    /* JSON  Event log file old */
    snprintf(ejlogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
             EVENTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "archive",
             pp_old->tm_mday);
             
    int exists_json_events = 0;
    FILE *fopnetestjsonevents;

    if ((fopnetestjsonevents = fopen(ejlogfile, "r"))) {
        exists_json_events = 1;
        fclose(fopnetestjsonevents);
    }

    if ((fopnetestjsonevents = fopen(ejlogfile_old, "r"))) {
        exists_json_events = 1;
        fclose(fopnetestjsonevents);
    }

    if (exists_json_events) {
        /* Only if there is a file to operate on. */
        OS_SignLog(ejlogfile, ejlogfile_old, 0);
        OS_CompressLog(ejlogfile);
    }
    
    
    /* alert logfile  */
    snprintf(alogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             ALERTS,
             cyear,
             months[cmon],
             "alerts",
             cday);
    /* alert logfile old  */
    snprintf(alogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             ALERTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "alerts",
             pp_old->tm_mday);
    OS_SignLog(alogfile, alogfile_old, 1);
    OS_CompressLog(alogfile);

    /* alert logfile  */
    snprintf(ajlogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
             ALERTS,
             cyear,
             months[cmon],
             "alerts",
             cday);
    /* alert logfile old  */
    snprintf(ajlogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
             ALERTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "alerts",
             pp_old->tm_mday);

    int exists = 0;
    FILE *fopnetest;

    if ((fopnetest = fopen(ajlogfile, "r"))) {
        exists = 1;
        fclose(fopnetest);
    }

    if ((fopnetest = fopen(ajlogfile_old, "r"))) {
        exists = 1;
        fclose(fopnetest);
    }

    if (exists) {
        /* Only if there is a file to operate on. */
        OS_SignLog(ajlogfile, ajlogfile_old, 1);
        OS_CompressLog(ajlogfile);
    }

    /* firewall events */
    snprintf(flogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             FWLOGS,
             cyear,
             months[cmon],
             "firewall",
             cday);
    /* firewall events old */
    snprintf(flogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             FWLOGS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "firewall",
             pp_old->tm_mday);
    OS_SignLog(flogfile, flogfile_old, 0);
    OS_CompressLog(flogfile);

    rotate_ossec_log(cday, cmon, cyear, pp_old);

    return;
}

