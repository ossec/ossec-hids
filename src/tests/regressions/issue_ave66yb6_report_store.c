/*
 * ANT-2026-AVE66YB6: os_ReportdStart() filed each alert in a sorted
 * OSStore, so N distinct locations cost O(N^2) strcmp walks and stalled
 * ossec-monitord. Distinct locations must cost about the same as one
 * shared location, and the printed tables stay ordered by count, then key.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ave66yb6_report_store
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "shared.h"

#define ORDER_USERS 64
#define SCALE_N 8000

static int failures = 0;

static void expect_str(const char *name, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("FAIL %s: got '%s' want '%s'\n", name, got, want);
        failures++;
    }
}

static void write_alert(FILE *fp, const char *location, int user)
{
    fprintf(fp, "** Alert 1700000000.%d: - syslog,errors,\n", user);
    fprintf(fp, "2023 Nov 14 22:13:20 %s\n", location);
    fprintf(fp, "Rule: 1002 (level 2) -> 'Unknown problem somewhere in the system.'\n");
    fprintf(fp, "User: user%04d\n", user);
    fprintf(fp, "some error\n\n");
}

static int run_report(const char *path, FILE *out)
{
    report_filter r_filter;

    memset(&r_filter, 0, sizeof(r_filter));
    r_filter.report_type = REPORT_TYPE_DAILY;
    r_filter.filename = (char *)path;
    r_filter.fp = out;
    os_ReportdStart(&r_filter);
    return (0);
}

static void find_table(FILE *fp, const char *hname)
{
    char line[512];
    char header[96];

    snprintf(header, sizeof(header), "Top entries for '%s':\r\n", hname);
    rewind(fp);
    while (fgets(line, sizeof(line), fp)) {
        if (strcmp(line, header) == 0) {
            fgets(line, sizeof(line), fp);
            return;
        }
    }
    printf("FAIL table '%s' not found\n", hname);
    failures++;
}

static void expect_entry(FILE *fp, const char *key, int count)
{
    char line[512] = "";
    char want[256] = " \r\n";

    if (key) {
        snprintf(want, sizeof(want), "%-78s|%-8d|\r\n", key, count);
    }
    if (!fgets(line, sizeof(line), fp)) {
        printf("FAIL %s: unexpected end of report\n", key ? key : "end of table");
        failures++;
        return;
    }
    expect_str(key ? key : "end of table", line, want);
}

static void check_order(void)
{
    int i;
    int fd;
    char path[] = "/tmp/ossec-ave66yb6-order-XXXXXX";
    char key[128];
    FILE *fp;
    FILE *out;

    fd = mkstemp(path);
    if (fd < 0 || (fp = fdopen(fd, "w")) == NULL) {
        perror("mkstemp");
        failures++;
        return;
    }

    memset(key, 'x', 80);
    key[80] = '\0';
    for (i = ORDER_USERS - 1; i >= 0; i--) {
        write_alert(fp, (i < 1) ? "b" : (i < 2) ? key : (i < 3) ? "a" :
                    (i < 5) ? "d" : (i < 8) ? "c" : "e", i);
    }
    fclose(fp);

    out = tmpfile();
    if (!out) {
        perror("tmpfile");
        unlink(path);
        failures++;
        return;
    }
    run_report(path, out);
    unlink(path);

    find_table(out, "Location");
    expect_entry(out, "e", ORDER_USERS - 8);
    expect_entry(out, "c", 3);
    expect_entry(out, "d", 2);
    expect_entry(out, "a", 1);
    expect_entry(out, "b", 1);
    key[74] = '.';
    key[75] = '.';
    key[76] = '\0';
    expect_entry(out, key, 1);
    expect_entry(out, NULL, 0);

    find_table(out, "Username");
    for (i = 0; i < ORDER_USERS; i++) {
        snprintf(key, sizeof(key), "user%04d", i);
        expect_entry(out, key, 1);
    }
    expect_entry(out, NULL, 0);
    fclose(out);
}

/* CPU seconds inside os_ReportdStart for SCALE_N alerts. */
static double report_cpu(int distinct)
{
    int i;
    int fd;
    char path[] = "/tmp/ossec-ave66yb6-scale-XXXXXX";
    char location[64];
    FILE *fp;
    FILE *out;
    clock_t t0, t1;

    fd = mkstemp(path);
    if (fd < 0 || (fp = fdopen(fd, "w")) == NULL) {
        perror("mkstemp");
        failures++;
        return (0);
    }
    for (i = 0; i < SCALE_N; i++) {
        if (distinct) {
            snprintf(location, sizeof(location), "/var/log/app-%05d.log", i);
        } else {
            snprintf(location, sizeof(location), "/var/log/app-00000.log");
        }
        write_alert(fp, location, 1);
    }
    fclose(fp);

    out = tmpfile();
    if (!out) {
        perror("tmpfile");
        unlink(path);
        failures++;
        return (0);
    }
    t0 = clock();
    run_report(path, out);
    t1 = clock();
    unlink(path);
    fclose(out);
    return (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
}

int main(void)
{
    double same, many;

    printf("=== ANT-2026-AVE66YB6 report store ===\n");
    check_order();

    same = report_cpu(0);
    many = report_cpu(1);
    printf("CPU  %d alerts, 1 location:  %.3f s\n", SCALE_N, same);
    printf("CPU  %d alerts, %d locations: %.3f s\n", SCALE_N, SCALE_N, many);

    /* The linked-list store is many times the one-location cost. A hash
     * lookup stays in the same neighborhood. */
    if (many > 0.15 && many > same * 8.0) {
        printf("FAIL: distinct locations cost %.1fx the single location\n",
               same > 0.0 ? many / same : many);
        failures++;
    }

    if (failures) {
        printf("FAIL: issue_ave66yb6_report_store (%d)\n", failures);
        return (1);
    }
    printf("PASS: issue_ave66yb6_report_store\n");
    return (0);
}
