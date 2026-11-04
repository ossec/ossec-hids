/*
 * ANT-2026-1HUE1BMJ: read_ossecalert must drain every complete alert in
 * one poll, not forward a single record and leave the rest until the next
 * loop_timeout (or lose them when alerts.log rotates).
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_1hue1bmj_ossecalert_drain
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "logcollector/logcollector.h"

#define MAX_EVENTS 32
#define ALERT_COUNT 3

int logr_queue = 0;
logreader *logff;

static logreader reader;
static char *events[MAX_EVENTS];
static int n_events;

int SendMSG(__attribute__((unused)) int queue, const char *message,
            __attribute__((unused)) const char *locmsg,
            __attribute__((unused)) char loc)
{
    if (n_events < MAX_EVENTS) {
        os_strdup(message, events[n_events]);
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
            events[n_events] = NULL;
        }
    }
}

static int write_alerts(FILE *fp, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (fprintf(fp,
                    "** Alert 1609459200.%d: - syslog,sshd,\n"
                    "2021 Jan 01 00:00:00 host->/var/log/secure\n"
                    "Rule: 5710 (level 5) -> 'sshd attempt.'\n"
                    "Src IP: 203.0.113.%d\n"
                    "Jan 01 00:00:00 host sshd[1]: Failed marker-%d\n"
                    "\n",
                    i + 1, i + 1, i + 1) < 0) {
            return -1;
        }
    }
    fflush(fp);
    rewind(fp);
    return 0;
}

static int count_marker(int marker)
{
    char needle[32];
    int i;
    int n = 0;

    snprintf(needle, sizeof(needle), "marker-%d", marker);
    for (i = 0; i < n_events && i < MAX_EVENTS; i++) {
        if (events[i] && strstr(events[i], needle) != NULL) {
            n++;
        }
    }
    return n;
}

int main(void)
{
    int rc = 0;
    int failed = 0;
    int i;

    printf("=== ANT-2026-1HUE1BMJ: ossecalert drains all alerts per poll ===\n");

    memset(&reader, 0, sizeof(reader));
    reader.file = "alerts.log";
    reader.fp = tmpfile();
    if (!reader.fp) {
        perror("tmpfile");
        return 1;
    }
    logff = &reader;
    max_lines = 0;

    if (write_alerts(reader.fp, ALERT_COUNT) != 0) {
        printf("  FAIL: could not write sample alerts\n");
        return 1;
    }

    logr_begin_read();
    clear_events();
    read_ossecalert(0, &rc, 0);

    if (n_events != ALERT_COUNT) {
        printf("  FAIL: one poll forwarded %d alerts, want %d\n",
               n_events, ALERT_COUNT);
        failed = 1;
    } else {
        printf("  ok: one poll forwarded %d alerts\n", n_events);
    }

    for (i = 0; i < ALERT_COUNT; i++) {
        if (count_marker(i + 1) != 1) {
            printf("  FAIL: marker-%d seen %d times\n",
                   i + 1, count_marker(i + 1));
            failed = 1;
        }
    }
    if (!failed) {
        printf("  ok: each alert body forwarded once\n");
    }

    /* Still honor the per-visit budget so one alerts.log cannot starve. */
    rewind(reader.fp);
    max_lines = 2;
    logr_begin_read();
    clear_events();
    read_ossecalert(0, &rc, 0);
    if (n_events != 2) {
        printf("  FAIL: max_lines=2 forwarded %d alerts, want 2\n", n_events);
        failed = 1;
    } else if (count_marker(1) != 1 || count_marker(2) != 1 ||
               count_marker(3) != 0) {
        printf("  FAIL: budgeted poll forwarded wrong markers\n");
        failed = 1;
    } else {
        printf("  ok: max_lines caps alerts per visit\n");
    }

    /* A torn trailing record must survive until the blank line arrives. */
    {
        FILE *w;

        clear_events();
        fclose(reader.fp);
        reader.fp = tmpfile();
        if (!reader.fp) {
            perror("tmpfile");
            return 1;
        }
        w = reader.fp;
        if (fprintf(w,
                    "** Alert 1609459200.9: - syslog,sshd,\n"
                    "2021 Jan 01 00:00:00 host->/var/log/secure\n"
                    "Rule: 5710 (level 5) -> 'sshd attempt.'\n"
                    "Jan 01 00:00:00 host sshd[1]: Failed marker-9\n"
                    "\n"
                    "** Alert 1609459200.10: - syslog,sshd,\n"
                    "2021 Jan 01 00:00:00 host->/var/log/secure\n"
                    "Rule: 5710 (level 5) -> 'sshd attempt.'\n"
                    "Jan 01 00:00:00 host sshd[1]: Failed marker-10") < 0) {
            printf("  FAIL: could not write torn trailing alert\n");
            return 1;
        }
        fflush(w);
        rewind(w);

        max_lines = 0;
        logr_begin_read();
        read_ossecalert(0, &rc, 0);
        if (n_events != 1 || count_marker(9) != 1 || count_marker(10) != 0) {
            printf("  FAIL: first poll with torn tail forwarded %d "
                   "(marker-9=%d marker-10=%d)\n",
                   n_events, count_marker(9), count_marker(10));
            failed = 1;
        } else {
            printf("  ok: complete alert sent; torn tail left unread\n");
        }

        /* Finish the torn record and poll again from where we left off. */
        {
            fpos_t torn_pos;

            fgetpos(w, &torn_pos);
            fseek(w, 0, SEEK_END);
            fputs("\n\n", w);
            fflush(w);
            fsetpos(w, &torn_pos);
        }

        logr_begin_read();
        clear_events();
        read_ossecalert(0, &rc, 0);
        if (n_events != 1 || count_marker(10) != 1) {
            printf("  FAIL: second poll after completing torn alert "
                   "forwarded %d (marker-10=%d)\n",
                   n_events, count_marker(10));
            failed = 1;
        } else {
            printf("  ok: completed torn alert forwarded on next poll\n");
        }
    }

    clear_events();
    fclose(reader.fp);

    if (failed) {
        printf("\nFAIL: issue_1hue1bmj_ossecalert_drain\n");
        return 1;
    }

    printf("\nPASS: issue_1hue1bmj_ossecalert_drain\n");
    return 0;
}
