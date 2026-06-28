/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

static const char *(monthss[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                 };

typedef struct report_worker_arg {
    int report_idx;
    int cday;
    int cmon;
    int cyear;
} report_worker_arg;

static pthread_mutex_t report_workers_mu;
static int report_active_workers = 0;
static pthread_once_t report_workers_once = PTHREAD_ONCE_INIT;

static void report_workers_mutex_init(void)
{
    os_mutex_init(&report_workers_mu, NULL);
}

static void report_workers_init(void)
{
    pthread_once(&report_workers_once, report_workers_mutex_init);
}

static void *report_worker(void *arg)
{
    report_worker_arg *work = (report_worker_arg *)arg;
    int s = work->report_idx;
    int cday = work->cday;
    int cmon = work->cmon;
    int cyear = work->cyear;
    char fname[256];
    char aname[256];

    os_block_worker_signals();
    free(work);

    fname[255] = '\0';
    aname[255] = '\0';
    snprintf(fname, sizeof(fname), "/logs/.report-%lu.log", (unsigned long)pthread_self());

    merror("%s: INFO: Starting daily reporting for '%s'", ARGV0, mond.reports[s]->title);
    mond.reports[s]->r_filter.fp = fopen(fname, "w+");
    if (!mond.reports[s]->r_filter.fp) {
        merror("%s: ERROR: Unable to open temporary reports file.", ARGV0);
        os_mutex_lock(&report_workers_mu);
        report_active_workers--;
        os_mutex_unlock(&report_workers_mu);
        return NULL;
    }

    snprintf(aname, sizeof(aname), "%s/%d/%s/ossec-%s-%02d.log",
             ALERTS, cyear, monthss[cmon], "alerts", cday);
    os_strdup(aname, mond.reports[s]->r_filter.filename);

    os_ReportdStart(&mond.reports[s]->r_filter);
    fflush(mond.reports[s]->r_filter.fp);

    fclose(mond.reports[s]->r_filter.fp);

    {
        struct stat sb;
        int sr;
        if ((sr = stat(fname, &sb)) < 0) {
            merror("Cannot stat %s: %s", fname, strerror(errno));
        } else if (sb.st_size == 0) {
            merror("%s: INFO: Report '%s' empty.", ARGV0, mond.reports[s]->title);
        } else if (OS_SendCustomEmail2(mond.reports[s]->emailto,
                                      mond.reports[s]->title,
                                      fname,
                                      &mond) != 0) {
            merror("%s: WARN: Unable to send report email.", ARGV0);
        }
    }

    if (unlink(fname) < 0) {
        merror("%s: ERROR: Cannot unlink file %s: %s", ARGV0, fname, strerror(errno));
    }

    free(mond.reports[s]->r_filter.filename);
    mond.reports[s]->r_filter.filename = NULL;

    os_mutex_lock(&report_workers_mu);
    report_active_workers--;
    os_mutex_unlock(&report_workers_mu);

    return NULL;
}

void generate_reports(int cday, int cmon, int cyear)
{
    int s = 0;

    if (!mond.smtpserver) {
        return;
    }

    if (mond.reports) {
        int threadcount = 0;
        int max_reports = 0;
        int max_report_workers;
        pthread_t *threads = NULL;

        report_workers_init();
        max_report_workers = getDefine_Int("monitord", "max_report_workers", 1, 16);

        while (mond.reports[max_reports]) {
            max_reports++;
        }

        if (max_reports == 0) {
            return;
        }

        os_calloc((size_t)max_reports, sizeof(pthread_t), threads);

        while (mond.reports[s]) {
            report_worker_arg *work;

            if (mond.reports[s]->emailto == NULL) {
                s++;
                continue;
            }

            while (1) {
                os_mutex_lock(&report_workers_mu);
                if (report_active_workers < max_report_workers) {
                    report_active_workers++;
                    os_mutex_unlock(&report_workers_mu);
                    break;
                }
                os_mutex_unlock(&report_workers_mu);
                sleep(1);
            }

            os_calloc(1, sizeof(report_worker_arg), work);
            work->report_idx = s;
            work->cday = cday;
            work->cmon = cmon;
            work->cyear = cyear;

            if (CreateThreadJoinable(&threads[threadcount], report_worker, work) != 0) {
                free(work);
                os_mutex_lock(&report_workers_mu);
                report_active_workers--;
                os_mutex_unlock(&report_workers_mu);
                merror("%s: ERROR: Unable to start report thread for '%s'", ARGV0,
                       mond.reports[s]->title);
                s++;
                continue;
            }

            threadcount++;
            s++;
        }

        {
            int i;
            for (i = 0; i < threadcount; i++) {
                pthread_join(threads[i], NULL);
            }
        }

        free(threads);
    }
    return;
}
