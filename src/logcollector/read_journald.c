#ifdef HAVE_SYSTEMD
#include "shared.h"
#include "logcollector.h"
#include <systemd/sd-journal.h>

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
    const char *jmsg = NULL;
    const char *jsrc = NULL;
    const char *jhst = NULL;
    size_t len;
    struct timeval tv;
    uint64_t curr_timestamp;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64];
    char final_msg[OS_MAXSTR];
    char sunitid[128];

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

    while ((ret = sd_journal_next(jrn)) > 0) {
        ret = sd_journal_get_data(
            jrn,
            "SYSLOG_IDENTIFIER",
            (const void **)&jsrc,
            &len
        );
        if (ret < 0 || jsrc == NULL) {
            continue;
        }

        /* Strip off "SYSLOG_IDENTIFIER=" prefix for unit comparison inline. */
        memset(sunitid, 0x00, sizeof(sunitid));
        strncpy(sunitid, (jsrc + 18), sizeof(sunitid) - 1);

        if (strncmp(sunitid, unit, sizeof(sunitid)) != 0 &&
                strncmp(unit, "all", 3) != 0 &&
                unit[0] != '/') {
            continue;
        }

        ret = sd_journal_get_data(jrn, "_HOSTNAME", (const void **)&jhst, &len);
        if (ret < 0 || jhst == NULL) {
            continue;
        }

        ret = sd_journal_get_data(jrn, "MESSAGE", (const void **)&jmsg, &len);
        if (ret < 0 || jmsg == NULL || len <= 8) {
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
            (char *)(jhst + 10),
            sunitid,
            (int)(len - 8),
            (char *)(jmsg + 8)
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
