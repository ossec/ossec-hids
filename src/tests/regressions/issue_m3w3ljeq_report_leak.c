/*
 * Regression: ossec-monitord daily reports must not leak per alert
 *
 * ANT-2026-M3W3LJEQ / CWE-401
 *
 * os_ReportdStart() used to leak the OS_StrBreak() group array (the loop
 * advanced the only pointer and free() was commented out) and the OSList
 * nodes in each top-entry table. Report work now runs in a thread, so
 * those chunks stayed for the life of ossec-monitord. A second report
 * over the same alerts must not grow the heap by hundreds of bytes per
 * alert. The AVE66YB6 hash-table change already frees the array and the
 * list nodes; this check locks that in.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_m3w3ljeq_report_leak
 *
 * Run:
 *   ./issue_m3w3ljeq_report_leak
 */

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"

#define REPORT_ALERTS 400
/* Pre-fix kept about 264 bytes for the group array alone. */
#define MAX_BYTES_PER_ALERT 64

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

static int heap_in_use(size_t *out)
{
#if defined(__GLIBC__)
# if defined(__GLIBC_PREREQ) && __GLIBC_PREREQ(2, 33)
    struct mallinfo2 mi = mallinfo2();
    *out = (size_t)mi.uordblks;
# else
    struct mallinfo mi = mallinfo();
    *out = (size_t)mi.uordblks;
# endif
    return (1);
#else
    (void)out;
    return (0);
#endif
}

static void write_alert(FILE *fp, int n)
{
    fprintf(fp, "** Alert 1700000000.%d: - syslog,errors,\n", n);
    fprintf(fp, "2023 Nov 14 22:13:20 host%04d\n", n % 17);
    fprintf(fp, "Rule: 1002 (level 2) -> 'Unknown problem somewhere in the system.'\n");
    fprintf(fp, "User: user%04d\n", n % 23);
    fprintf(fp, "some error %d\n\n", n);
}

static void run_report(const char *path)
{
    report_filter r_filter;
    FILE *out;

    out = fopen("/dev/null", "w");
    if (!out) {
        out = fopen("/tmp/ossec-m3w3ljeq-out", "w");
    }
    memset(&r_filter, 0, sizeof(r_filter));
    r_filter.report_type = REPORT_TYPE_DAILY;
    r_filter.filename = (char *)path;
    r_filter.fp = out ? out : stdout;
    os_ReportdStart(&r_filter);
    if (out && out != stdout) {
        fclose(out);
    }
}

int main(void)
{
    char path[] = "/tmp/ossec-m3w3ljeq-XXXXXX";
    FILE *fp;
    int fd;
    int i;
    size_t before;
    size_t after;
    double per;

    printf("monitord daily report leak\n");

    fd = mkstemp(path);
    expect(fd >= 0, "create an alerts file");
    if (fd < 0) {
        return 1;
    }
    fp = fdopen(fd, "w");
    expect(fp != NULL, "open the alerts file");
    if (!fp) {
        close(fd);
        return 1;
    }
    for (i = 0; i < REPORT_ALERTS; i++) {
        write_alert(fp, i);
    }
    fclose(fp);

    /* Warm up once so later growth is from leftover report state. */
    run_report(path);
    if (!heap_in_use(&before)) {
        printf("SKIP: heap measurement needs glibc mallinfo\n");
        unlink(path);
        return 0;
    }
    run_report(path);
    if (!heap_in_use(&after)) {
        printf("SKIP: heap measurement needs glibc mallinfo\n");
        unlink(path);
        return 0;
    }

    if (after >= before) {
        per = (double)(after - before) / (double)REPORT_ALERTS;
    } else {
        per = 0.0;
    }
    printf("  heap after second report: %+ld bytes (%.1f per alert)\n",
           (long)after - (long)before, per);
    expect(per < (double)MAX_BYTES_PER_ALERT,
           "a second report does not keep hundreds of bytes per alert");

    unlink(path);
    if (failures) {
        printf("FAIL: %d report leak check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
