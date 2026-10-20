/*
 * Regression for OS_CleanMSG_ex date-probe bounds (ANT-2026-8R0YEF8T / CWE-125).
 *
 * 1) Empty log text: the Mär umlaut repair must not read past the message.
 * 2) Suricata date with only one trailing space (27 chars): must not advance
 *    lf->log past the dual full_log copy (loglen > 26 / += 28 off-by-one).
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_cleanevent_date_oob
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <time.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/cleanevent.h"
#include "analysisd/config.h"
#include "analysisd/analysisd.h"

_Config Config;
__thread time_t c_time;
__thread int __crt_hour;
__thread int __crt_wday;
char __shost[512];
OSDecoderInfo *NULL_Decoder = NULL;
int alert_only = 1;

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static Eventinfo *new_lf(void)
{
    Eventinfo *lf;

    os_calloc(1, sizeof(*lf), lf);
    Zero_Eventinfo(lf);
    return lf;
}

/* Empty log: place UTF-8 ä canaries immediately past the message NUL.
 * Unguarded pieces[1]/pieces[2] reads rewrite them to 'M'/'a'. */
static void test_empty_log_umlaut_guard(void)
{
    Eventinfo *lf;
    char buf[64];
    unsigned char *canary;
    size_t msg_len;

    printf("--- empty log (umlaut over-read) ---\n");

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "1:/var/log/messages:");
    msg_len = strlen(buf);
    canary = (unsigned char *)(buf + msg_len + 1);
    canary[0] = 195; /* C3 */
    canary[1] = 164; /* A4 */

    lf = new_lf();
    CHECK(OS_CleanMSG_ex(buf, lf, time(NULL), 0) == 0, "OS_CleanMSG_ex accepts empty log");
    CHECK(canary[0] == 195 && canary[1] == 164,
          "umlaut canary past empty log was not rewritten");

    Free_Eventinfo(lf);
}

/* 27-char Suricata-shaped date + one space: skip must not leave lf->log
 * past the second copy's terminating NUL. */
static void test_suricata_date_only(void)
{
    Eventinfo *lf;
    char msg[128];
    const char *body = "01/28/1979-09:13:16.240702 ";
    size_t loglen;
    ptrdiff_t off;

    printf("--- Suricata date-only (27 chars) ---\n");
    CHECK(strlen(body) == 27, "fixture is exactly 27 characters");

    snprintf(msg, sizeof(msg), "1:/var/log/suricata/fast.log:%s", body);
    loglen = strlen(body) + 1;

    lf = new_lf();
    CHECK(OS_CleanMSG_ex(msg, lf, time(NULL), 0) == 0, "OS_CleanMSG_ex accepts date-only line");
    CHECK(lf->full_log != NULL && lf->log != NULL, "full_log and log are set");

    off = lf->log - lf->full_log;
    /* Second copy occupies [loglen, 2*loglen); NUL at 2*loglen-1. A pointer
     * at 2*loglen is the unused spare byte (the Suricata off-by-one). */
    CHECK(off >= 0 && (size_t)off < 2 * loglen,
          "lf->log stays inside the dual full_log string copies");
    CHECK(strcmp(lf->log, body) == 0,
          "date-only line is not misclassified as Suricata (log unchanged)");

    Free_Eventinfo(lf);
}

/* Real Suricata line (date + two spaces + text) must still strip the date. */
static void test_suricata_real_line(void)
{
    Eventinfo *lf;
    char msg[256];
    const char *body = "01/28/1979-09:13:16.240702  [**] ETA alert";

    printf("--- Suricata real line ---\n");
    snprintf(msg, sizeof(msg), "1:/var/log/suricata/fast.log:%s", body);

    lf = new_lf();
    CHECK(OS_CleanMSG_ex(msg, lf, time(NULL), 0) == 0, "OS_CleanMSG_ex accepts Suricata line");
    CHECK(lf->log && strcmp(lf->log, "[**] ETA alert") == 0,
          "Suricata date stripped; alert text remains");

    Free_Eventinfo(lf);
}

/* Mär syslog month still repairs and strips the timestamp. */
static void test_umlaut_month_still_works(void)
{
    Eventinfo *lf;
    char msg[256];

    printf("--- Mär syslog month ---\n");
    /* M + UTF-8 ä + "r 02 17:30:52 host msg" */
    snprintf(msg, sizeof(msg),
             "1:/var/log/messages:M\xc3\xa4r 02 17:30:52 host testprog: hello");

    lf = new_lf();
    CHECK(OS_CleanMSG_ex(msg, lf, time(NULL), 0) == 0, "OS_CleanMSG_ex accepts Mär line");
    CHECK(lf->log && strstr(lf->log, "hello") != NULL,
          "Mär line decodes; message body reachable");

    Free_Eventinfo(lf);
}

int main(void)
{
    memset(&Config, 0, sizeof(Config));
    Config.decoder_order_size = 8;
    strncpy(__shost, "managerhost", sizeof(__shost) - 1);
    c_time = time(NULL);

    printf("=== ANT-2026-8R0YEF8T: OS_CleanMSG_ex date-probe bounds ===\n");

    test_empty_log_umlaut_guard();
    test_suricata_date_only();
    test_suricata_real_line();
    test_umlaut_month_still_works();

    if (failures) {
        printf("\nFAIL: issue_cleanevent_date_oob (%d)\n", failures);
        return 1;
    }

    printf("\nPASS: issue_cleanevent_date_oob\n");
    return 0;
}
