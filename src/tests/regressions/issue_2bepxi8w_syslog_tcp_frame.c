/*
 * ANT-2026-2BEPXI8W: TCP syslog must forward every complete line in a recv.
 *
 * Pre-fix, syslog_client_worker() cut at the first newline and parked the
 * rest without scanning again. Lines that shared a segment were glued onto
 * the next segment or dropped. This test drives syslog_tcp_drain_complete_lines
 * the worker uses after each append.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_2bepxi8w_syslog_tcp_frame
 */

#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "remoted/remoted.h"

const char *__local_name = "issue-2bepxi8w-syslog-tcp-frame";

__thread remoted_listener *remoted_self = NULL;

keystore keys;
remoted logr;
remoted_listener remoted_listeners[REMOTE_LISTENERS_MAX];
remoted_listener *remoted_secure_listener = NULL;
volatile sig_atomic_t remoted_shutting_down = 0;
volatile sig_atomic_t remoted_force_exit = 0;

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

#define MAX_MSGS 16
#define MSG_LEN  256

typedef struct {
    int count;
    char msgs[MAX_MSGS][MSG_LEN];
} send_capture;

static int capture_send(const char *msg, void *ctx)
{
    send_capture *cap = (send_capture *)ctx;

    if (!msg || cap->count >= MAX_MSGS) {
        return (-1);
    }
    strncpy(cap->msgs[cap->count], msg, MSG_LEN - 1);
    cap->msgs[cap->count][MSG_LEN - 1] = '\0';
    cap->count++;
    return (0);
}

static void append_segment(char *storage, size_t *sb_used, const char *segment)
{
    size_t len = strlen(segment);

    memcpy(storage + *sb_used, segment, len + 1);
    *sb_used += len;
}

static void test_multi_line_one_segment(void)
{
    char storage[OS_MAXSTR + 2];
    size_t sb_used = 0;
    send_capture cap;

    memset(storage, 0, sizeof(storage));
    memset(&cap, 0, sizeof(cap));

    append_segment(storage, &sb_used,
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line A\n"
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line B\n"
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line C\n");

    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "drain returns success for three complete lines");
    CHECK(cap.count == 3,
          "one segment with three lines yields three events");
    CHECK(cap.count >= 1 &&
          strcmp(cap.msgs[0], "Oct 11 10:00:00 fw1 sshd[1]: line A") == 0,
          "first event is line A without <PRI>");
    CHECK(cap.count >= 2 &&
          strcmp(cap.msgs[1], "Oct 11 10:00:00 fw1 sshd[1]: line B") == 0,
          "second event is line B without <PRI>");
    CHECK(cap.count >= 3 &&
          strcmp(cap.msgs[2], "Oct 11 10:00:00 fw1 sshd[1]: line C") == 0,
          "third event is line C without <PRI>");
    CHECK(sb_used == 0 && storage[0] == '\0',
          "no incomplete remainder after three complete lines");
}

static void test_second_segment_after_park(void)
{
    char storage[OS_MAXSTR + 2];
    size_t sb_used = 0;
    send_capture cap;

    memset(storage, 0, sizeof(storage));
    memset(&cap, 0, sizeof(cap));

    append_segment(storage, &sb_used,
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line A\n"
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line B\n"
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line C\n");
    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "first drain succeeds");

    append_segment(storage, &sb_used,
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line D\n");
    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "second drain succeeds");
    CHECK(cap.count == 4,
          "A+B+C then D yields four separate events");
    CHECK(cap.count >= 4 &&
          strcmp(cap.msgs[3], "Oct 11 10:00:00 fw1 sshd[1]: line D") == 0,
          "fourth event is line D alone");
    CHECK(sb_used == 0,
          "buffer empty after line D");
}

static void test_embedded_nul_in_segment(void)
{
    char storage[OS_MAXSTR + 2];
    size_t sb_used = 0;
    send_capture cap;
    const char *a = "<13>Oct 11 10:00:00 fw1 sshd[1]: line A";
    const char *b = "<13>Oct 11 10:00:00 fw1 sshd[1]: line B\n";
    const char *c = "<13>Oct 11 10:00:00 fw1 sshd[1]: line C\n";
    size_t a_len = strlen(a);
    size_t b_len = strlen(b);
    size_t c_len = strlen(c);
    int i;

    memset(storage, 0, sizeof(storage));
    memset(&cap, 0, sizeof(cap));

    /* Simulate a recv that embedded a NUL, then the worker maps NULs to
     * spaces before drain (same as read_syslog). */
    memcpy(storage, a, a_len);
    storage[a_len] = '\0';
    memcpy(storage + a_len + 1, b, b_len);
    memcpy(storage + a_len + 1 + b_len, c, c_len + 1);
    for (i = 0; i < (int)(a_len + 1 + b_len + c_len); i++) {
        if (storage[i] == '\0') {
            storage[i] = ' ';
        }
    }
    sb_used = a_len + 1 + b_len + c_len;

    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "NUL-sanitized segment drains");
    CHECK(cap.count == 2,
          "lines after an embedded NUL still become events");
    CHECK(cap.count >= 2 &&
          strcmp(cap.msgs[1], "Oct 11 10:00:00 fw1 sshd[1]: line C") == 0,
          "line C after NUL is forwarded");
}

static void test_crlf_and_split(void)
{
    char storage[OS_MAXSTR + 2];
    size_t sb_used = 0;
    send_capture cap;

    memset(storage, 0, sizeof(storage));
    memset(&cap, 0, sizeof(cap));

    append_segment(storage, &sb_used,
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line A\r\n"
                   "<13>Oct 11 10:00:00 fw1 sshd[1]: line B\r\n");
    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "CRLF drain succeeds");
    CHECK(cap.count == 2,
          "CRLF segment yields two events");
    CHECK(cap.count >= 1 && strchr(cap.msgs[0], '\r') == NULL,
          "CRLF strip removes CR from line A");
    CHECK(cap.count >= 2 &&
          strcmp(cap.msgs[1], "Oct 11 10:00:00 fw1 sshd[1]: line B") == 0,
          "CRLF strip leaves line B intact");

    memset(&cap, 0, sizeof(cap));
    append_segment(storage, &sb_used, "<13>Oct 11 10:00:00 fw1 sshd[1]: lin");
    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "incomplete prefix kept without sending");
    CHECK(cap.count == 0, "no event for incomplete line");
    append_segment(storage, &sb_used, "e E\n");
    CHECK(syslog_tcp_drain_complete_lines(storage, &sb_used,
                                          capture_send, &cap) == 0,
          "split line completes on second segment");
    CHECK(cap.count == 1 &&
          strcmp(cap.msgs[0], "Oct 11 10:00:00 fw1 sshd[1]: line E") == 0,
          "split line reassembled as one event");
}

int main(void)
{
    printf("ANT-2026-2BEPXI8W syslog TCP framing regression\n");
    test_multi_line_one_segment();
    test_second_segment_after_park();
    test_embedded_nul_in_segment();
    test_crlf_and_split();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
