#include "shared.h"
#include "logcollector.h"
#include <systemd/sd-journal.h>

int prime_sd_journal(sd_journal **jrn) {
  int ret;
  ret = sd_journal_open(jrn, SD_JOURNAL_LOCAL_ONLY);
  ret = sd_journal_get_fd(*(jrn));
  ret = sd_journal_seek_tail(*(jrn));
  // prime sd_journal_next before the reader loop
  ret = sd_journal_previous(*(jrn));
  return ret;
}

void *sd_read_journal(__attribute__((unused)) char *journal) {
  sd_journal *jrn;
  int ret;
  const char *data;
  size_t len;
  struct timeval tv;
  uint64_t curr_timestamp;
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], final_msg[OS_MAXSTR];

  prime_sd_journal(&jrn);
  ret = sd_journal_next(jrn);
  // Anything negative is an error
  while (ret >= 0) {
    // No messages, wait for data
    if (ret == 0) {
      while ((sd_journal_wait(jrn, (uint64_t)-1)) == SD_JOURNAL_NOP) {
        sleep(1);
      }
    } else {
      // Read data
      ret = sd_journal_get_data(jrn, "MESSAGE", (const void **)&data, &len);
      // Read timestamp and format it
      ret = sd_journal_get_realtime_usec(jrn, &curr_timestamp);
      tv.tv_sec = curr_timestamp / 1000000;
      tv.tv_usec = curr_timestamp % 1000000;
      nowtime = tv.tv_sec;
      nowtm = localtime(&nowtime);
      strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
      // Build and send message
      snprintf(
        final_msg,
        sizeof(final_msg),
        "%s.%06ld %.*s\n",
        tmbuf,
        tv.tv_usec,
        (int) len,
        data
      );
      if (SendMSG(logr_queue, final_msg, "WinEvtLog", LOCALFILE_MQ) < 0) {
          merror(QUEUE_SEND, ARGV0);
      }
    }
    // Prime next iteration condition & journal position
    ret = sd_journal_next(jrn);
  }
  // Clean up after ourselves and bail
  sd_journal_close(jrn);
  return NULL;
}
