/*
 * ANT-2026-QY1SHLVV: syslog TCP workers must release idle/dead clients.
 *
 * Pre-fix, SO_RCVTIMEO EAGAIN was always retried (including after EOF left
 * a stale errno), ETIMEDOUT from unanswered keepalive was also retried, and
 * idle connections were never dropped when the pool had waiters. This test
 * covers the close/continue decision and the atomic idle-drop claim that
 * prevents a timeout herd from dropping every quiet forwarder for one waiter.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_qy1shlvv_syslog_tcp_idle
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "remoted/remoted.h"
#include "thread_pool.h"

const char *__local_name = "issue-qy1shlvv-syslog-tcp-idle";

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

static void test_should_close_on_recv(void)
{
    /* Peer closed after an idle timeout left EAGAIN in errno. */
    CHECK(syslog_tcp_should_close_on_recv(0, EAGAIN, 0) == 1,
          "EOF closes even when errno is still EAGAIN");
    CHECK(syslog_tcp_should_close_on_recv(0, 0, 0) == 1,
          "EOF closes when errno is clear");

    /* Quiet SO_RCVTIMEO: keep the forwarder unless a drop was claimed. */
    CHECK(syslog_tcp_should_close_on_recv(-1, EAGAIN, 0) == 0,
          "read timeout keeps the connection while no drop is claimed");
    CHECK(syslog_tcp_should_close_on_recv(-1, EWOULDBLOCK, 0) == 0,
          "EWOULDBLOCK timeout keeps the connection while no drop is claimed");
    CHECK(syslog_tcp_should_close_on_recv(-1, EAGAIN, 1) == 1,
          "read timeout closes when an idle drop was claimed");

    /* Unanswered TCP keepalive probes must free the worker. */
    CHECK(syslog_tcp_should_close_on_recv(-1, ETIMEDOUT, 0) == 1,
          "ETIMEDOUT (keepalive) closes even when no drop is claimed");
    CHECK(syslog_tcp_should_close_on_recv(-1, ECONNRESET, 0) == 1,
          "ECONNRESET closes");
}

static void test_idle_drop_claim_no_herd(void)
{
    thread_pool pool;
    int claims = 0;
    int i;

    memset(&pool, 0, sizeof(pool));
    os_mutex_init(&pool.mu, NULL);
    pool.pending = 1;

    for (i = 0; i < 5; i++) {
        if (thread_pool_should_drop_idle(&pool)) {
            claims++;
        }
    }
    CHECK(claims == 1,
          "only one idle drop is claimed for a single queued client");

    pool.pending = 3;
    claims = 0;
    for (i = 0; i < 5; i++) {
        if (thread_pool_should_drop_idle(&pool)) {
            claims++;
        }
    }
    /* idle_drop_claims was already 1; pending 3 allows two more. */
    CHECK(claims == 2,
          "additional claims track newly queued clients only");

    /* Simulate: two waiters, one idle drop claimed; dequeue that waiter and
     * the remaining waiter must still be able to free a quiet connection. */
    pool.pending = 2;
    pool.idle_drop_claims = 1;
    pool.pending--;
    if (pool.idle_drop_claims > 0) {
        pool.idle_drop_claims--;
    }
    CHECK(pool.pending == 1 && pool.idle_drop_claims == 0,
          "dequeue retires the claim for the waiter that was served");
    CHECK(thread_pool_should_drop_idle(&pool) == 1,
          "remaining waiter can claim after a prior claim was dequeued");
    CHECK(thread_pool_should_drop_idle(&pool) == 0,
          "no further claims once pending waiters are covered");

    CHECK(thread_pool_should_drop_idle(NULL) == 0,
          "NULL pool does not claim a drop");

    os_mutex_destroy(&pool.mu);
}

int main(void)
{
    printf("issue_qy1shlvv_syslog_tcp_idle:\n");
    test_should_close_on_recv();
    test_idle_drop_claim_no_herd();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return (1);
    }
    printf("OK\n");
    return (0);
}
