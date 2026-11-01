/*
 * ANT-2026-J9QHSFRD: a newline in the agent-chosen location must not survive
 * OS_CleanMSG, or FTS / alerts / archives can treat the rest as a second line
 * (forging another agent's first-time-seen record).
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_j9qhsfrd_fts_location_newline
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"

_Config Config;
__thread time_t c_time;
OSDecoderInfo *NULL_Decoder = NULL;
char __shost[512] = "localhost";
__thread int __crt_hour = 0;
__thread int __crt_wday = 0;
int alert_only = 0;
int full_output = 0;

EventNode *OS_GetLastEvent(void)
{
    return NULL;
}

int OS_CleanMSG(char *msg, Eventinfo *lf);

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

int main(void)
{
    char msg[2048];
    Eventinfo lf;

    printf("ANT-2026-J9QHSFRD location newline must not forge FTS lines\n");

    /*
     * Remoted shape after SECURE_MQ rewrite: location is
     * "(web01) any->" + agent-chosen path, which may contain a newline and a
     * forged second FTS record for another agent.
     */
    snprintf(msg, sizeof(msg),
             "1:(web01) any->/var/log/auth.log\n"
             "sshd  mallory      (db01) any->/var/log/auth.log:"
             "Oct 12 10:00:00 web01 sshd[4711]: Accepted password for bob");

    memset(&lf, 0, sizeof(lf));
    c_time = time(NULL);

    if (OS_CleanMSG(msg, &lf) < 0) {
        printf("FAIL: OS_CleanMSG returned error\n");
        return 1;
    }

    CHECK(lf.location != NULL, "location set");
    CHECK(lf.location && strchr(lf.location, '\n') == NULL,
          "location contains no newline (cannot split fts-queue)");
    CHECK(lf.location &&
          strstr(lf.location, "(web01) any->/var/log/auth.log") == lf.location,
          "legitimate location prefix preserved at start");
    /* Control strip collapses the inject into one line; a second FTS record
     * is not created. The plant text may remain as trash in the same line. */
    CHECK(lf.location && strchr(lf.location, '\r') == NULL,
          "location contains no CR either");

    free(lf.location);
    free(lf.full_log);
    free(lf.agent_name);

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
