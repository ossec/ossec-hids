#ifdef HAVE_SYSTEMD
#include "shared.h"
#include "logcollector.h"
#include <systemd/sd-journal.h>

/* Copy the value after the first '=' in a journal field blob of length len.
 * sd_journal_get_data() returns a non-NUL-terminated mmap window; callers
 * must not treat data as a C string or retain the pointer across another
 * get_data() call. */
static int journal_copy_value(char *dst, size_t dst_sz,
                              const void *data, size_t len)
{
    const char *p;
    const char *eq;
    size_t vlen;

    if (dst == NULL || dst_sz == 0 || data == NULL || len == 0) {
        return -1;
    }

    p = (const char *)data;
    eq = memchr(p, '=', len);
    if (eq == NULL || eq == p) {
        return -1;
    }

    vlen = len - (size_t)(eq - p) - 1;
    if (vlen >= dst_sz) {
        vlen = dst_sz - 1;
    }
    memcpy(dst, eq + 1, vlen);
    dst[vlen] = '\0';
    return 0;
}

void *prime_sd_journal(int pos) {
    int ret;
    sd_journal *jrn;

    int jfd;

    ret = sd_journal_open(&jrn, SD_JOURNAL_LOCAL_ONLY);
    if (ret < 0) {
        merror("%s: ERROR: Unable to open journal", ARGV0);
        return NULL;
    }

    jfd = sd_journal_get_fd(jrn);
    if (jfd < 0) {
        merror("%s: ERROR: Unable to get journal fd", ARGV0);
        sd_journal_close(jrn);
        logff[pos].fd = 0;
        return NULL;
    }
    logff[pos].fd = jfd;

    ret = sd_journal_seek_tail(jrn);
    if (ret < 0) {
        merror("%s: ERROR: Unable to seek journal tail", ARGV0);
        sd_journal_close(jrn);
        logff[pos].ptr = NULL;
        logff[pos].fd = 0;
        return NULL;
    }

    /* Prime sd_journal_next before the reader loop. */
    ret = sd_journal_previous(jrn);
    if (ret < 0) {
        merror("%s: ERROR: Unable to seek journal previous", ARGV0);
    }

    return (void *)jrn;
}

void *sd_read_journal(int pos, int *rc, int drop_it) {
    sd_journal *jrn = (sd_journal *) logff[pos].ptr;
    const char *unit = logff[pos].file;
    int ret;
    int lines = 0;
    const char *jmsg = NULL;
    const char *jsrc = NULL;
    const char *jhst = NULL;
    const char *msg_eq;
    size_t len;
    size_t msg_vlen;
    struct timeval tv;
    uint64_t curr_timestamp;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64];
    char final_msg[OS_MAXSTR];
    char sunitid[128];
    char shost[128];

    (void)drop_it;
    *rc = 0;

    if (jrn == NULL) {
        jrn = logff[pos].ptr = prime_sd_journal(pos);
        if (jrn == NULL) {
            *rc = -1;
            return NULL;
        }
    }

    if (unit == NULL) {
        unit = "all";
    }

    /* Consume journal inotify events so files created after open (rotation /
     * vacuum) are attached to this handle. Without this, sd_journal_next()
     * stays at EOF on the archived file until logcollector restarts
     * (ANT-2026-K99OKMJP). */
    ret = sd_journal_process(jrn);
    if (ret < 0) {
        merror("%s: ERROR: Unable to process journal changes.", ARGV0);
        sd_journal_close(jrn);
        logff[pos].ptr = NULL;
        logff[pos].fd = 0;
        *rc = -1;
        return (NULL);
    }
    if (ret == SD_JOURNAL_INVALIDATE) {
        verbose("%s: INFO: Journal file set changed; continuing from current cursor.",
                ARGV0);
    }

    /* After max_lines entries the other sources get their turn; ret is 0
     * then, as at the end of the journal, so it is not closed below. */
    while ((ret = (max_lines == 0 || lines++ < max_lines) ?
                  sd_journal_next(jrn) : 0) > 0) {
        ret = sd_journal_get_data(
            jrn,
            "SYSLOG_IDENTIFIER",
            (const void **)&jsrc,
            &len
        );
        if (ret < 0 || jsrc == NULL ||
                journal_copy_value(sunitid, sizeof(sunitid), jsrc, len) < 0) {
            continue;
        }

        if (strncmp(sunitid, unit, sizeof(sunitid)) != 0 &&
                strncmp(unit, "all", 3) != 0 &&
                unit[0] != '/') {
            continue;
        }

        ret = sd_journal_get_data(jrn, "_HOSTNAME", (const void **)&jhst, &len);
        if (ret < 0 || jhst == NULL ||
                journal_copy_value(shost, sizeof(shost), jhst, len) < 0) {
            continue;
        }

        ret = sd_journal_get_data(jrn, "MESSAGE", (const void **)&jmsg, &len);
        if (ret < 0 || jmsg == NULL || len == 0) {
            continue;
        }
        msg_eq = memchr(jmsg, '=', len);
        if (msg_eq == NULL || msg_eq == jmsg) {
            continue;
        }
        msg_vlen = len - (size_t)(msg_eq - jmsg) - 1;
        if (msg_vlen == 0) {
            continue;
        }

        ret = sd_journal_get_realtime_usec(jrn, &curr_timestamp);
        if (ret < 0) {
            continue;
        }

        tv.tv_sec  = curr_timestamp / 1000000;
        tv.tv_usec = curr_timestamp % 1000000;
        nowtime = tv.tv_sec;
        nowtm = localtime(&nowtime);
        if (nowtm == NULL) {
            continue;
        }

        /* Mimic syslog-ng ISO8601 timestamps for analysisd parsing. */
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%T%z", nowtm);
        if (strlen(tmbuf) >= 2) {
            tmbuf[strlen(tmbuf) - 2] = '\0';
        }

        snprintf(
            final_msg,
            sizeof(final_msg),
            "%s:00 %s %s: %.*s\n",
            tmbuf,
            shost,
            sunitid,
            (int)msg_vlen,
            msg_eq + 1
        );

        if (SendMSG(logr_queue, final_msg, "journald", LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND, ARGV0);
        }
    }

    if (ret < 0) {
        sd_journal_close(jrn);
        logff[pos].ptr = NULL;
        logff[pos].fd = 0;
        *rc = -1;
    }

    return NULL;
}

#endif //HAVE_SYSTEMD
