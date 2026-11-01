/* Minimal sd-journal stand-in for journald logcollector regressions. */
#ifndef OSSEC_STUB_SD_JOURNAL_H
#define OSSEC_STUB_SD_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#define SD_JOURNAL_LOCAL_ONLY (1 << 0)
#define SD_JOURNAL_NOP 0
#define SD_JOURNAL_APPEND 1
#define SD_JOURNAL_INVALIDATE 2

typedef struct sd_journal sd_journal;

int sd_journal_open(sd_journal **ret, int flags);
void sd_journal_close(sd_journal *j);
int sd_journal_get_fd(sd_journal *j);
int sd_journal_process(sd_journal *j);
int sd_journal_seek_tail(sd_journal *j);
int sd_journal_previous(sd_journal *j);
int sd_journal_next(sd_journal *j);
int sd_journal_get_data(sd_journal *j, const char *field,
                        const void **data, size_t *length);
int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret);

/* Test helpers (not part of libsystemd). */
void stub_journal_reset(void);
int stub_journal_append(const char *identifier, const char *host,
                        const char *message, uint64_t usec);
void stub_journal_rotate(void);
void stub_journal_fail_process(int fail);
int stub_journal_process_calls(void);

#endif
