/*
 * Regression: date-based logs drop the tail written before the name changes
 *
 * ANT-2026-YGX1KKKT / CWE-223
 *
 * update_fname() replaces a strftime <location> as soon as the expanded
 * name differs, and the poll loop then fclose()s the old file. Lines
 * appended since the previous poll are never read, so they never reach
 * ossec-analysisd. The reader must run while logff[i].file is still the
 * old name. A reader that returns after one record has to be called
 * again until the position stops moving.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ygx1kkkt_dated_log_tail
 *
 * Run:
 *   ./issue_ygx1kkkt_dated_log_tail
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "logcollector.h"

const char *__local_name __attribute__((weak)) =
    "issue-ygx1kkkt-dated-log-tail";

int update_fname(int i);

static int failures = 0;
static char seen[4][128];
static char seen_loc[4][OS_FLSIZE + 1];
static int seen_n;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

/* One record per call, like a reader that does not drain the file itself. */
static void *read_one_line(int pos, int *rc, int drop_it)
{
    char buf[128];

    (void)drop_it;
    *rc = 0;
    if (!fgets(buf, sizeof(buf), logff[pos].fp)) {
        return NULL;
    }
    if (seen_n < 4) {
        snprintf(seen[seen_n], sizeof(seen[seen_n]), "%s", buf);
        snprintf(seen_loc[seen_n], sizeof(seen_loc[seen_n]), "%s",
                 logff[pos].file ? logff[pos].file : "");
        seen_n++;
    }
    return NULL;
}

static void reset_seen(void)
{
    seen_n = 0;
    memset(seen, 0, sizeof(seen));
    memset(seen_loc, 0, sizeof(seen_loc));
}

int main(void)
{
    char dir[] = "/tmp/ygx1kkkt-XXXXXX";
    char old_path[OS_FLSIZE + 1];
    char tmpl[OS_FLSIZE + 1];
    char expanded[OS_FLSIZE + 1];
    char new_path[OS_FLSIZE + 1];
    logreader *slot;
    time_t now;
    struct tm *pt;
    FILE *fp;
    int rc;

    printf("date-based log tail before the name changes\n");
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 1;
    }

    snprintf(old_path, sizeof(old_path), "%s/access-old.log", dir);
    snprintf(tmpl, sizeof(tmpl), "%s/access-%%Y.log", dir);
    now = time(NULL);
    pt = localtime(&now);
    if (!pt || strftime(new_path, sizeof(new_path), tmpl, pt) == 0) {
        printf("FAIL: could not expand the date template\n");
        rmdir(dir);
        return 1;
    }
    expect(strcmp(new_path, old_path) != 0, "template expands to a new name");

    fp = fopen(old_path, "w");
    if (!fp) {
        perror(old_path);
        rmdir(dir);
        return 1;
    }
    fputs("already-read\n", fp);
    fputs("late-one\n", fp);
    fputs("late-two\n", fp);
    fclose(fp);

    slot = calloc(1, sizeof(*slot));
    if (!slot) {
        printf("FAIL: calloc\n");
        unlink(old_path);
        rmdir(dir);
        return 1;
    }
    logff = slot;
    os_strdup(old_path, slot->file);
    os_strdup(tmpl, slot->ffile);
    slot->logformat = "syslog";
    slot->read = read_one_line;
    slot->fp = fopen(old_path, "r");
    if (!slot->fp) {
        perror("fopen");
        return 1;
    }
    /* Previous poll already consumed the first line. */
    expect(fgets(expanded, sizeof(expanded), slot->fp) != NULL,
           "previous poll consumed the earlier line");
    expect(strcmp(expanded, "already-read\n") == 0, "consumed line is the earlier one");

    reset_seen();
    rc = update_fname(0);
    expect(rc == 1, "expanded name differs, so the file rotates");
    expect(seen_n == 2, "both lines written since the last poll are read");
    expect(seen_n > 0 && strcmp(seen[0], "late-one\n") == 0, "first unread line is kept");
    expect(seen_n > 1 && strcmp(seen[1], "late-two\n") == 0, "second unread line is kept");
    expect(seen_n > 0 && strcmp(seen_loc[0], old_path) == 0,
           "the line is reported under the old file name");
    expect(slot->file && strcmp(slot->file, new_path) == 0,
           "the stored name is the new expansion after the read");

    /* Same expanded name: nothing new to read. */
    reset_seen();
    rc = update_fname(0);
    expect(rc == 0, "a second check in the same period does not rotate");
    expect(seen_n == 0, "an unchanged name does not read again");

    if (slot->fp) {
        fclose(slot->fp);
    }
    free(slot->file);
    free(slot->ffile);
    free(slot);
    unlink(old_path);
    rmdir(dir);

    if (failures) {
        printf("FAIL: %d dated-log tail check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
