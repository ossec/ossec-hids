#ifdef HAVE_SYSTEMD
#include "shared.h"
#include "logcollector.h"
#include <systemd/sd-journal.h>

int prime_sd_journal(sd_journal **jrn) {
  int ret;
  ret = sd_journal_open(jrn, SD_JOURNAL_LOCAL_ONLY);
  if (ret < 0) {
    merror("%s: ERROR: Unable to open journal", ARGV0);
    return ret;
  }
  ret = sd_journal_get_fd(*(jrn));
  if (ret < 0) {
    merror("%s: ERROR: Unable to get journal fd", ARGV0);
    return ret;
  }
  ret = sd_journal_seek_tail(*(jrn));
  if (ret < 0) {
    merror("%s: ERROR: Unable to seek journal tail", ARGV0);
    return ret;
  }
  // prime sd_journal_next before the reader loop
  ret = sd_journal_previous(*(jrn));
  if (ret < 0) {
    merror("%s: ERROR: Unable to seek journal previous", ARGV0);
  }
  return ret;
}

void *sd_read_journal(__attribute__((unused)) char *unit) {
  sd_journal *jrn;
  int ret;
  const char *jmsg, *jsrc, *jhst;
  size_t len;
  struct timeval tv;
  uint64_t curr_timestamp;
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], final_msg[OS_MAXSTR];

  ret = prime_sd_journal(&jrn);
  if (ret < 0) {
    merror("%s: ERROR: Unable to prime journal", ARGV0);
    return NULL;
  }
  ret = sd_journal_next(jrn);
  // Anything negative is an error
  while (ret >= 0) {
    // No messages, wait for data
    if (ret == 0) {
      while ((sd_journal_wait(jrn, (uint64_t)-1)) == SD_JOURNAL_NOP) {
        sleep(1);
      }
    } else {
      // Check if data is coming from the unit starting with our passed selector
      ret = sd_journal_get_data(
        jrn,
        "SYSLOG_IDENTIFIER",
        (const void **)&jsrc,
        &len
      );
      // Strip off "SYSLOG_IDENTIFIER=" prefix for unit comparison inline
      if (strstr((char *)(jsrc + 18), unit) == (char *)(jsrc + 18) ) {
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
        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
        // Build and send message
        snprintf(
          final_msg,
          sizeof(final_msg),
          "%s.%06ld %s %s %.*s\n",
          tmbuf,
          tv.tv_usec,
          // Strip the "_HOSTNAME", "SYSLOG_IDENTIFIER=" and "MESSAGE=" prefixes
          (char *)(jhst + 10),
          (char *)(jsrc + 18),
          (int) len,
          (char *)(jmsg + 8)
        );
        if (SendMSG(logr_queue, final_msg, "journald", LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND, ARGV0);
        }
      // Clean journal output buffers
      strcpy(jhst,"");
      strcpy(jmsg,"");
      }
    }
    strcpy(jsrc,"");
    // Prime next iteration condition & journal position
    ret = sd_journal_next(jrn);
  }
  // Clean up after ourselves and bail
  sd_journal_close(jrn);
  return NULL;
}

#endif //HAVE_SYSTEMD
