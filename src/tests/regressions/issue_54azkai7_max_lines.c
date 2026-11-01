/*
 * Regression for ANT-2026-54AZKAI7: one file reader must not drain an
 * unbounded amount of new content in a single visit, or every other
 * localfile waits until that file hits EOF.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_54azkai7_max_lines
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "logcollector/logcollector.h"

#define MAX_EVENTS 128
#define BURST_LINES 40
#define LINE_BUDGET 5

int logr_queue = 0;
logreader *logff;

static logreader readers[2];
static char *events[MAX_EVENTS];
static char *locs[MAX_EVENTS];
static int n_events;

int SendMSG(__attribute__((unused)) int queue, const char *message,
            const char *locmsg, __attribute__((unused)) char loc)
{
    if (n_events < MAX_EVENTS) {
        os_strdup(message, events[n_events]);
        os_strdup(locmsg, locs[n_events]);
    }
    n_events++;
    return 0;
}

int StartMQ(__attribute__((unused)) const char *path,
            __attribute__((unused)) short int type)
{
    return 0;
}

static void clear_events(void)
{
    while (n_events > 0) {
        n_events--;
        if (n_events < MAX_EVENTS) {
            free(events[n_events]);
            free(locs[n_events]);
            events[n_events] = NULL;
            locs[n_events] = NULL;
        }
    }
}

static int count_loc(const char *name)
{
    int i;
    int n = 0;

    for (i = 0; i < n_events && i < MAX_EVENTS; i++) {
        if (strcmp(locs[i], name) == 0) {
            n++;
        }
    }
    return n;
}

static int write_lines(FILE *fp, const char *prefix, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (fprintf(fp, "%s-%d\n", prefix, i) < 0) {
            return -1;
        }
    }
    fflush(fp);
    rewind(fp);
    return 0;
}

int main(void)
{
    int rc = 0;
    int failed = 0;
    int i;
    int from_busy;
    int from_other;

    printf("=== ANT-2026-54AZKAI7: per-visit line budget ===\n");

    memset(readers, 0, sizeof(readers));
    readers[0].file = "busy.log";
    readers[0].fp = tmpfile();
    readers[1].file = "other.log";
    readers[1].fp = tmpfile();
    if (!readers[0].fp || !readers[1].fp) {
        printf("FAIL: tmpfile\n");
        return 1;
    }
    logff = readers;

    if (write_lines(readers[0].fp, "busy", BURST_LINES) != 0 ||
            write_lines(readers[1].fp, "other", 1) != 0) {
        printf("FAIL: write_lines\n");
        return 1;
    }

    /* Simulate the daemon: reset the budget, visit busy, then other. */
    max_lines = LINE_BUDGET;
    clear_events();
    logr_begin_read();
    read_syslog(0, &rc, 0);
    from_busy = count_loc("busy.log");
    logr_begin_read();
    read_syslog(1, &rc, 0);
    from_other = count_loc("other.log");

    if (from_busy != LINE_BUDGET) {
        printf("FAIL: busy.log produced %d event(s) in one visit (want %d)\n",
               from_busy, LINE_BUDGET);
        failed = 1;
    } else {
        printf("ok: busy.log stopped after %d line(s)\n", from_busy);
    }

    if (from_other != 1) {
        printf("FAIL: other.log produced %d event(s) after busy visit (want 1)\n",
               from_other);
        failed = 1;
    } else {
        printf("ok: other.log got its turn in the same pass\n");
    }

    /* Next visit continues where the budget left off. */
    clear_events();
    logr_begin_read();
    read_syslog(0, &rc, 0);
    from_busy = count_loc("busy.log");
    if (from_busy != LINE_BUDGET) {
        printf("FAIL: second busy visit produced %d event(s) (want %d)\n",
               from_busy, LINE_BUDGET);
        failed = 1;
    } else if (events[0] == NULL || strcmp(events[0], "busy-5") != 0) {
        printf("FAIL: second visit should resume at busy-5, got '%s'\n",
               events[0] ? events[0] : "(null)");
        failed = 1;
    } else {
        printf("ok: second visit resumed at '%s'\n", events[0]);
    }

    /* Whitespace-only lines (NUL holes become spaces) must not be forwarded. */
    clear_events();
    max_lines = 0;
    rewind(readers[0].fp);
    ftruncate(fileno(readers[0].fp), 0);
    {
        char hole[64];

        memset(hole, '\0', sizeof(hole) - 1);
        hole[sizeof(hole) - 1] = '\n';
        fwrite(hole, 1, sizeof(hole), readers[0].fp);
        fprintf(readers[0].fp, "after-hole\n");
        fflush(readers[0].fp);
        rewind(readers[0].fp);
    }
    logr_begin_read();
    read_syslog(0, &rc, 0);
    if (n_events != 1 || events[0] == NULL ||
            strcmp(events[0], "after-hole") != 0) {
        printf("FAIL: expected only after-hole, got %d event(s) first='%s'\n",
               n_events, n_events && events[0] ? events[0] : "(null)");
        failed = 1;
    } else {
        printf("ok: blank/NUL hole line not forwarded\n");
    }

    for (i = 0; i < 2; i++) {
        if (readers[i].fp) {
            fclose(readers[i].fp);
        }
    }
    clear_events();

    if (failed) {
        printf("\nFAIL: issue_54azkai7_max_lines\n");
        return 1;
    }

    printf("\nPASS: issue_54azkai7_max_lines\n");
    return 0;
}
