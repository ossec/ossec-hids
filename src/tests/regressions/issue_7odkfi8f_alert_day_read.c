/*
 * Regression: Read_FileMon skips alerts already in a newly opened file
 *
 * ANT-2026-7ODKFI8F / CWE-223
 *
 * Handle_Queue() seeks to the end unless CRALERT_READ_ALL is set. After
 * the 2008 flag change, Read_FileMon() still passed 0 when the file was
 * not open yet and when the day changed. Alerts analysisd had already
 * written were skipped by csyslogd, maild, and dbd. Init_FileQueue()
 * still tails, so a restart does not repeat the day's alerts.
 *
 * This binary compiles file-queue.c with DEFAULTDIR=/tmp/ossec-7odkfi8f.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_7odkfi8f_alert_day_read
 *
 * Run:
 *   ./issue_7odkfi8f_alert_day_read
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "file-queue.h"
#include "read-alert.h"

const char *__local_name = "issue-7odkfi8f-alert-day-read";

#define BASE "/tmp/ossec-7odkfi8f/logs/alerts/2021/Jan"
#define DAY1 BASE "/ossec-alerts-01.log"
#define DAY2 BASE "/ossec-alerts-02.log"

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static int ensure_dir(void)
{
    if (mkdir("/tmp/ossec-7odkfi8f", 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir("/tmp/ossec-7odkfi8f/logs", 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir("/tmp/ossec-7odkfi8f/logs/alerts", 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir("/tmp/ossec-7odkfi8f/logs/alerts/2021", 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir(BASE, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int write_alert(const char *path, const char *comment)
{
    FILE *fp = fopen(path, "w");

    if (!fp) {
        perror(path);
        return -1;
    }
    fprintf(fp,
            "** Alert 1609459200.1: - syslog,sshd,\n"
            "2021 Jan 01 00:00:00 host->/var/log/secure\n"
            "Rule: 5710 (level 5) -> '%s'\n"
            "event body\n"
            "\n",
            comment);
    fclose(fp);
    return 0;
}

static void jan_tm(struct tm *tm, int mday)
{
    memset(tm, 0, sizeof(*tm));
    tm->tm_year = 121;
    tm->tm_mon = 0;
    tm->tm_mday = mday;
}

/* Alerts written before the reader opens today's file must be returned. */
static void test_open_reads_existing(void)
{
    file_queue fq;
    struct tm tm;
    alert_data *al;

    printf("--- open a file that already holds an alert ---\n");
    if (write_alert(DAY2, "already written") != 0) {
        failures++;
        return;
    }

    memset(&fq, 0, sizeof(fq));
    fq.day = 2;
    fq.year = 2021;
    memcpy(fq.mon, "Jan", 4);
    strncpy(fq.file_name, DAY2, MAX_FQUEUE);
    jan_tm(&tm, 2);

    al = Read_FileMon(&fq, &tm, 0);
    expect(al != NULL, "alert already in the file is not skipped");
    if (al) {
        expect(al->comment && strstr(al->comment, "already written") != NULL,
               "alert text is the one written before open");
        FreeAlertData(al);
    }
    if (fq.fp) {
        fclose(fq.fp);
    }
}

/* Alerts written to the new day's file before the day switch are returned. */
static void test_day_change_reads_existing(void)
{
    file_queue fq;
    struct tm tm;
    alert_data *al;
    FILE *old;

    printf("--- day change onto a file that already holds an alert ---\n");
    old = fopen(DAY1, "w");
    if (!old) {
        perror(DAY1);
        failures++;
        return;
    }
    fclose(old);
    if (write_alert(DAY2, "after midnight") != 0) {
        failures++;
        return;
    }

    memset(&fq, 0, sizeof(fq));
    fq.day = 1;
    fq.year = 2021;
    memcpy(fq.mon, "Jan", 4);
    fq.fp = fopen(DAY1, "r");
    if (!fq.fp) {
        perror(DAY1);
        failures++;
        return;
    }
    jan_tm(&tm, 2);

    al = Read_FileMon(&fq, &tm, 0);
    expect(al != NULL, "first alerts of the new day are not skipped");
    if (al) {
        expect(al->comment && strstr(al->comment, "after midnight") != NULL,
               "alert text is from the new day's file");
        FreeAlertData(al);
    }
    if (fq.fp) {
        fclose(fq.fp);
    }
}

/* A daemon start still tails, so it does not resend today's alerts. */
static void test_init_still_tails(void)
{
    file_queue fq;
    struct tm tm;
    alert_data *al;

    printf("--- Init_FileQueue still seeks to the end ---\n");
    if (write_alert(DAY2, "before restart") != 0) {
        failures++;
        return;
    }
    memset(&fq, 0, sizeof(fq));
    jan_tm(&tm, 2);
    expect(Init_FileQueue(&fq, &tm, 0) == 0, "Init_FileQueue opens the file");
    al = Read_FileMon(&fq, &tm, 0);
    expect(al == NULL, "startup does not reread alerts already in the file");
    if (al) {
        FreeAlertData(al);
    }
    if (fq.fp) {
        fclose(fq.fp);
    }
}

int main(void)
{
    if (ensure_dir() != 0) {
        perror("mkdir");
        return 1;
    }

    test_open_reads_existing();
    test_day_change_reads_existing();
    test_init_still_tails();

    unlink(DAY1);
    unlink(DAY2);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
