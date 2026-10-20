/*
 * Regression for the OSSECAlert decoder after #1668: an agent event with no
 * syslog hostname reaches the decoder with an owned lf->hostname
 * (EF_FREE_HNAME set). The decoder aliases lf->hostname to lf->location,
 * so Free_Eventinfo() used to free the same buffer twice.
 *
 * ANT-2026-5ZOE8CQ9 / CWE-415
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_1668_ossecalert_hostname
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

void *OSSECAlert_Decoder_Exec(Eventinfo *lf);

static int run_case(const char *name, const char *msg, int want_rule)
{
    Eventinfo *lf;
    OSDecoderInfo decoder_info;
    char *buf;
    int rc;
    int failed = 0;

    printf("--- %s ---\n", name);
    os_calloc(1, sizeof(*lf), lf);
    Zero_Eventinfo(lf);
    memset(&decoder_info, 0, sizeof(decoder_info));
    lf->decoder_info = &decoder_info;

    os_strdup(msg, buf);
    rc = OS_CleanMSG_ex(buf, lf, time(NULL), 0);
    free(buf);

    if (rc != 0) {
        printf("FAIL: OS_CleanMSG_ex returned %d\n", rc);
        Free_Eventinfo(lf);
        return 1;
    }

    OSSECAlert_Decoder_Exec(lf);

    /* An owned hostname must never share storage with location. */
    if ((lf->flags & EF_FREE_HNAME) && lf->hostname == lf->location) {
        printf("FAIL: hostname aliases location while EF_FREE_HNAME is set\n");
        failed = 1;
    }
    if (want_rule && !lf->generated_rule) {
        printf("FAIL: decoder did not run to completion\n");
        failed = 1;
    }
    if (!failed) {
        printf("OK: hostname='%s' location='%s' flags=0x%x\n",
               lf->hostname ? lf->hostname : "",
               lf->location ? lf->location : "", lf->flags);
    }

    /* glibc aborts here on the double free. */
    Free_Eventinfo(lf);
    return failed;
}

int main(void)
{
    int failed = 0;
    static int rule_1002;

    memset(&Config, 0, sizeof(Config));
    Config.decoder_order_size = 8;
    Config.g_rules_hash = OSHash_Create();
    OSHash_Add(Config.g_rules_hash, "1002", &rule_1002);
    strncpy(__shost, "managerhost", sizeof(__shost) - 1);
    c_time = time(NULL);

    printf("=== Issue 1668: OSSECAlert decoder hostname ownership ===\n");

    /* No syslog header: hostname is an owned copy of the agent name.
     * Trailing field without ';' takes the decoder's early return. */
    failed |= run_case(
        "agent, no header, early return",
        "1:(agent1) any->/var/log/app.log:"
        "ossec: Alert Level: 3; Rule: 1002 - x; Location: y; z",
        0);

    /* Same, but the decoder runs to the end (two spaces after ';'). */
    failed |= run_case(
        "agent, no header, full decode",
        "1:(agent1) any->/var/log/app.log:"
        "ossec: Alert Level: 3; Rule: 1002 - x; Location: y;  text",
        1);

    /* Syslog header: hostname points into the log buffer on entry. */
    failed |= run_case(
        "agent, syslog header",
        "1:(agent1) any->/var/log/app.log:"
        "Jan 15 12:00:00 web1 ossec: Alert Level: 3; Rule: 1002 - x; "
        "Location: y;  text",
        1);

    if (failed) {
        printf("\nFAIL: issue_1668_ossecalert_hostname\n");
        return 1;
    }

    printf("\nPASS: issue_1668_ossecalert_hostname\n");
    return 0;
}
