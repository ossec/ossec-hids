#ifdef HAVE_SYSTEMD
#include "shared.h"
#include "logcollector.h"
#include <systemd/sd-journal.h>

void *prime_sd_journal(int pos) {
  int ret;
  sd_journal *jrn;
  ret = sd_journal_open(&jrn, SD_JOURNAL_LOCAL_ONLY);
  if (ret < 0) {
    merror("%s: ERROR: Unable to open journal", ARGV0);
    return NULL;
  }
  // For future use
  logff[pos].fd = sd_journal_get_fd(jrn);
  if (ret < 0) {
    merror("%s: ERROR: Unable to get journal fd", ARGV0);
    return NULL;
  }
  ret = sd_journal_seek_tail(jrn);
  if (ret < 0) {
    merror("%s: ERROR: Unable to seek journal tail", ARGV0);
    return NULL;
  }
  // prime sd_journal_next before the reader loop
  ret = sd_journal_previous(jrn);
  if (ret < 0) {
    merror("%s: ERROR: Unable to seek journal previous", ARGV0);
  }
  return (void *)jrn;
}

void *sd_read_journal(int pos, int *rc, int drop_it) {
  sd_journal *jrn = (sd_journal *) logff[pos].ptr;
  char *unit = logff[pos].file;
  int ret;
  const char *jmsg = NULL, *jsrc = NULL, *jhst = NULL;
  size_t len;
  struct timeval tv;
  uint64_t curr_timestamp;
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], final_msg[OS_MAXSTR], sunitid[128];
  *rc = 0;

  if (jrn == NULL) {
     jrn = logff[pos].ptr = prime_sd_journal(pos);
     if (jrn == NULL) {
        merror("%s: ERROR: Unable to prime journal", ARGV0);
        return NULL;
     }
  }

  if (unit == NULL) {
      unit = logff[pos].file = "all";
  }

  // Anything negative is an error
  while (ret > 0) {
      ret = sd_journal_next(jrn);
      // below 0 Means problem or journal file vanished. Open it again next time and
      // try again
      // 0 means there is no new messages
      if (ret < 0) {
         sd_journal_close(jrn);
         logff[pos].ptr = NULL;
         *rc = -1;
         continue;
      } else if (!ret) {
         continue;
      }
      // Check if data is coming from the unit starting with our passed selector
      ret = sd_journal_get_data(
        jrn,
        "SYSLOG_IDENTIFIER",
        (const void **)&jsrc,
        &len
      );
      // Strip off "SYSLOG_IDENTIFIER=" prefix for unit comparison inline
      memset(sunitid, 0x00, 128);
      strncpy(sunitid, (jsrc + 18), 128);
      // If incoming systemd unit is unit or unit is 'all' which means log everything
      // or unit starts which char '/' which means unit is directory and
      // user have malconfigured journald
      if (!strncmp(sunitid, unit, 128) || !strncmp(unit, "all", 3) || unit[0] == '/') {
        // Read hostname
        ret = sd_journal_get_data(jrn, "_HOSTNAME", (const void **)&jhst, &len);
        // Read data
        ret = sd_journal_get_data(jrn, "MESSAGE", (const void **)&jmsg, &len);
        // Read timestamp and format it
        ret = sd_journal_get_realtime_usec(jrn, &curr_timestamp);
        tv.tv_sec  = curr_timestamp / 1000000;
        tv.tv_usec = curr_timestamp % 1000000;
        nowtime = tv.tv_sec;
        nowtm = localtime(&nowtime);
        // We have to mimic syslog-ng for time and date for OSSEC-HIDS
        // time and date parser.
        // Syslog-ng It produces broken ISO8601 strings like
        // 2020-04-01T12:00:00+03:00
        // Journald reader triest to mimics it.
        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%T%z", nowtm);
        tmbuf[strlen(tmbuf) - 2] = '\0';
        // Build and send message
        snprintf(
          final_msg,
          sizeof(final_msg),
          "%s:00 %s %s: %.*s\n",
          tmbuf,
          // Strip the "_HOSTNAME", "SYSLOG_IDENTIFIER=" and "MESSAGE=" prefixes
          (char *)(jhst + 10),
          sunitid,
          (int) len,
          (char *)(jmsg + 8)
        );
        if (SendMSG(logr_queue, final_msg, "journald", LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND, ARGV0);
        }
        // These pointers are only valid until next one
        // So it's safe to just to NULL them
        jhst = NULL;
        jmsg = NULL;
    }
    // This pointer is only valid until next one
    // So it's safe to just to NULL them
    jsrc = NULL;
    // Prime next iteration condition & journal position
    ret = sd_journal_next(jrn);
  }
  return NULL;
}

#endif //HAVE_SYSTEMD
