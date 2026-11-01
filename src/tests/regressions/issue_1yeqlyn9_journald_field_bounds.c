/*
 * Regression for ANT-2026-1YEQLYN9: sd_journal_get_data() returns a
 * non-NUL-terminated mmap blob and a length. Treating it as a C string
 * (strncpy / %s) over-reads into the next object and can use a host-name
 * pointer after a later get_data() has invalidated it.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_1yeqlyn9_journald_field_bounds
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "shared.h"
#include "logcollector/logcollector.h"
#include "systemd/sd-journal.h"

#define MAX_EVENTS 4

int logr_queue = 0;
logreader *logff;

static logreader reader;
static char *events[MAX_EVENTS];
static int n_events;

struct stub_entry {
    char id_blob[64];
    size_t id_len;
    char host_blob[64];
    size_t host_len;
    char msg_blob[128];
    size_t msg_len;
    uint64_t usec;
};

struct sd_journal {
    int cursor;
    int n_entries;
    int process_calls;
    int fd;
    int host_live; /* cleared when MESSAGE is fetched */
    struct stub_entry entries[4];
};

static sd_journal g_journal;
static int g_open;

void stub_journal_reset(void)
{
    memset(&g_journal, 0, sizeof(g_journal));
    g_journal.cursor = -1;
    g_journal.fd = 7;
    g_open = 0;
}

/* Pack FIELD=value plus a deliberate trailing junk byte outside len. */
static void pack_field(char *blob, size_t blob_sz, size_t *out_len,
                       const char *field, const char *value, unsigned char junk)
{
    int n = snprintf(blob, blob_sz, "%s=%s", field, value);

    if (n < 0 || (size_t)n >= blob_sz - 1) {
        *out_len = 0;
        return;
    }
    *out_len = (size_t)n;
    blob[n] = (char)junk;
    if ((size_t)n + 1 < blob_sz) {
        blob[n + 1] = 'Z';
    }
    if ((size_t)n + 2 < blob_sz) {
        blob[n + 2] = '\0';
    }
}

int stub_journal_append(const char *identifier, const char *host,
                        const char *message, uint64_t usec)
{
    struct stub_entry *e;

    if (g_journal.n_entries >= 4) {
        return -1;
    }
    e = &g_journal.entries[g_journal.n_entries];
    pack_field(e->id_blob, sizeof(e->id_blob), &e->id_len,
               "SYSLOG_IDENTIFIER", identifier, 0x02);
    pack_field(e->host_blob, sizeof(e->host_blob), &e->host_len,
               "_HOSTNAME", host, 0x02);
    pack_field(e->msg_blob, sizeof(e->msg_blob), &e->msg_len,
               "MESSAGE", message, 0x00);
    e->usec = usec;
    g_journal.n_entries++;
    return 0;
}

int sd_journal_open(sd_journal **ret, int flags)
{
    (void)flags;
    if (g_open) {
        return -EBUSY;
    }
    g_open = 1;
    g_journal.cursor = -1;
    *ret = &g_journal;
    return 0;
}

void sd_journal_close(sd_journal *j)
{
    (void)j;
    g_open = 0;
}

int sd_journal_get_fd(sd_journal *j)
{
    return j ? j->fd : -EINVAL;
}

int sd_journal_process(sd_journal *j)
{
    if (!j) {
        return -EINVAL;
    }
    j->process_calls++;
    return SD_JOURNAL_NOP;
}

int sd_journal_seek_tail(sd_journal *j)
{
    if (!j) {
        return -EINVAL;
    }
    j->cursor = j->n_entries > 0 ? j->n_entries - 1 : -1;
    return 0;
}

int sd_journal_previous(sd_journal *j)
{
    if (!j || j->cursor <= 0) {
        if (j) {
            j->cursor = -1;
        }
        return 0;
    }
    j->cursor--;
    return 1;
}

int sd_journal_next(sd_journal *j)
{
    if (!j) {
        return -EINVAL;
    }
    if (j->cursor + 1 >= j->n_entries) {
        return 0;
    }
    j->cursor++;
    j->host_live = 1;
    return 1;
}

int sd_journal_get_data(sd_journal *j, const char *field,
                        const void **data, size_t *length)
{
    struct stub_entry *e;

    if (!j || j->cursor < 0 || j->cursor >= j->n_entries) {
        return -EADDRNOTAVAIL;
    }
    e = &j->entries[j->cursor];

    if (strcmp(field, "SYSLOG_IDENTIFIER") == 0) {
        *data = e->id_blob;
        *length = e->id_len;
        return 0;
    }
    if (strcmp(field, "_HOSTNAME") == 0) {
        *data = e->host_blob;
        *length = e->host_len;
        j->host_live = 1;
        return 0;
    }
    if (strcmp(field, "MESSAGE") == 0) {
        /* Invalidate hostname blob: libsystemd may remap after this call. */
        memset(e->host_blob, 0xAA, sizeof(e->host_blob) - 1);
        e->host_blob[sizeof(e->host_blob) - 1] = '\0';
        j->host_live = 0;
        *data = e->msg_blob;
        *length = e->msg_len;
        return 0;
    }
    return -ENOENT;
}

int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret)
{
    if (!j || j->cursor < 0 || j->cursor >= j->n_entries) {
        return -EADDRNOTAVAIL;
    }
    *ret = j->entries[j->cursor].usec;
    return 0;
}

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

int main(void)
{
    int rc = 0;
    int failed = 0;
    uint64_t t0 = 1700000000ULL * 1000000ULL;

    printf("=== ANT-2026-1YEQLYN9: journal field copies must honor length ===\n");

    stub_journal_reset();
    /* 14-char identifier: classic over-read length class. */
    stub_journal_append("NetworkManager", "testhost",
                        "device eth0 down", t0);

    memset(&reader, 0, sizeof(reader));
    reader.file = "all";
    reader.logformat = "journald";
    logff = &reader;

    clear_events();
    sd_read_journal(0, &rc, 0);

    if (n_events != 1 || events[0] == NULL) {
        printf("FAIL: expected one journal event, got %d\n", n_events);
        failed = 1;
    } else if (strchr(events[0], '\x02') != NULL ||
               strstr(events[0], "NetworkManagerZ") != NULL ||
               strstr(events[0], "testhostZ") != NULL ||
               memchr(events[0], 0xAA, strlen(events[0])) != NULL) {
        printf("FAIL: over-read or stale host pointer in '%.120s'\n", events[0]);
        failed = 1;
    } else if (strstr(events[0], "NetworkManager") == NULL ||
               strstr(events[0], "testhost") == NULL ||
               strstr(events[0], "device eth0 down") == NULL) {
        printf("FAIL: missing expected fields in '%.120s'\n", events[0]);
        failed = 1;
    } else {
        printf("ok: identifier and host copied without trailing junk\n");
    }

    /* Location filter must match the clean identifier. */
    clear_events();
    stub_journal_reset();
    stub_journal_append("NetworkManager", "testhost",
                        "device eth0 down", t0);
    reader.file = "NetworkManager";
    reader.ptr = NULL;
    sd_read_journal(0, &rc, 0);
    if (n_events != 1) {
        printf("FAIL: location NetworkManager matched %d event(s)\n", n_events);
        failed = 1;
    } else {
        printf("ok: <location>NetworkManager</location> matches\n");
    }

    clear_events();

    if (failed) {
        printf("\nFAIL: issue_1yeqlyn9_journald_field_bounds\n");
        return 1;
    }

    printf("\nPASS: issue_1yeqlyn9_journald_field_bounds\n");
    return 0;
}
