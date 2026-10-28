/*
 * Regression for #1668: agent-forwarded syslog must keep the device
 * hostname for <hostname> matching, with the OSSEC agent name separate.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_1668_agent_hostname
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
#include "analysisd/accumulator.h"

_Config Config;
__thread time_t c_time;
__thread int __crt_hour;
__thread int __crt_wday;
char __shost[512];
OSDecoderInfo *NULL_Decoder = NULL;
int alert_only = 1;

static int expect_eq(const char *label, const char *got, const char *want)
{
    if (want == NULL) {
        if (got != NULL && got[0] != '\0') {
            printf("FAIL: %s: expected NULL/empty, got '%s'\n", label, got);
            return 1;
        }
        return 0;
    }
    if (!got || strcmp(got, want) != 0) {
        printf("FAIL: %s: expected '%s', got '%s'\n",
               label, want, got ? got : "(null)");
        return 1;
    }
    return 0;
}


/* Parse msg, decode it as decoder/id with the given srcip, run Accumulate()
 * and return the srcip the event ends up with (caller frees). */
static char *accumulate_srcip(const char *msg, OSDecoderInfo *decoder,
                              const char *id, const char *srcip)
{
    Eventinfo *lf;
    char *buf;
    char *got = NULL;

    os_calloc(1, sizeof(*lf), lf);
    Zero_Eventinfo(lf);

    os_strdup(msg, buf);
    if (OS_CleanMSG_ex(buf, lf, time(NULL), 0) != 0) {
        printf("FAIL: OS_CleanMSG_ex failed for '%s'\n", msg);
        free(buf);
        Free_Eventinfo(lf);
        return NULL;
    }
    free(buf);

    lf->decoder_info = decoder;
    os_strdup(id, lf->id);
    if (srcip) {
        os_strdup(srcip, lf->srcip);
    }

    Accumulate(lf);

    if (lf->srcip) {
        os_strdup(lf->srcip, got);
    }
    Free_Eventinfo(lf);
    return got;
}

/* ANT-2026-ZQN8MYKG: two agents with the same device hostname and decoder id
 * must not share accumulator state. */
static int run_accumulate_case(void)
{
    OSDecoderInfo decoder;
    char *got;
    int failed = 0;

    printf("--- accumulator keyed on agent, not log hostname ---\n");

    memset(&decoder, 0, sizeof(decoder));
    decoder.name = "openldap";

    if (!Accumulate_Init()) {
        printf("FAIL: Accumulate_Init\n");
        return 1;
    }

    /* agent A seeds hostname ldap1 / conn 3000 with its own srcip */
    got = accumulate_srcip(
        "1:(agentA) 127.0.0.2->/var/log/slapd.log:"
        "Oct 11 10:00:00 ldap1 slapd[20872]: conn=3000 fd=64 ACCEPT from IP=203.0.113.9:33957",
        &decoder, "3000", "203.0.113.9");
    free(got);

    /* agent B's event for the same hostname/id carries no srcip of its own */
    got = accumulate_srcip(
        "1:(agentB) 127.0.0.3->/var/log/slapd.log:"
        "Oct 11 10:00:01 ldap1 slapd[20872]: conn=3000 op=0 RESULT tag=97 err=49",
        &decoder, "3000", NULL);
    failed |= expect_eq("agentB srcip after agentA seed", got, NULL);
    free(got);

    /* the same agent still accumulates across its own lines */
    got = accumulate_srcip(
        "1:(agentB) 127.0.0.3->/var/log/slapd.log:"
        "Oct 11 10:00:02 ldap1 slapd[20872]: conn=3001 fd=64 ACCEPT from IP=10.0.0.50:40000",
        &decoder, "3001", "10.0.0.50");
    free(got);
    got = accumulate_srcip(
        "1:(agentB) 127.0.0.3->/var/log/slapd.log:"
        "Oct 11 10:00:03 ldap1 slapd[20872]: conn=3001 op=0 RESULT tag=97 err=49",
        &decoder, "3001", NULL);
    failed |= expect_eq("agentB srcip from own ACCEPT", got, "10.0.0.50");
    free(got);

    Accumulate_CleanUp();

    if (!failed) {
        printf("OK: accumulator entries are scoped per agent\n");
    }
    return failed;
}

static int run_case(const char *name, const char *msg,
                    const char *want_hostname, const char *want_agent,
                    const char *want_location_substr)
{
    Eventinfo *lf;
    char *buf;
    int rc;
    int failed = 0;

    printf("--- %s ---\n", name);
    os_calloc(1, sizeof(*lf), lf);
    Zero_Eventinfo(lf);

    os_strdup(msg, buf);
    rc = OS_CleanMSG_ex(buf, lf, time(NULL), 0);
    free(buf);

    if (rc != 0) {
        printf("FAIL: OS_CleanMSG_ex returned %d\n", rc);
        Free_Eventinfo(lf);
        return 1;
    }

    failed |= expect_eq("hostname", lf->hostname, want_hostname);
    failed |= expect_eq("agent_name", lf->agent_name, want_agent);

    if (want_location_substr) {
        if (!lf->location || !strstr(lf->location, want_location_substr)) {
            printf("FAIL: location '%s' missing '%s'\n",
                   lf->location ? lf->location : "(null)", want_location_substr);
            failed = 1;
        }
    }

    if (!failed) {
        printf("OK: hostname='%s' agent_name='%s' location='%s'\n",
               lf->hostname ? lf->hostname : "",
               lf->agent_name ? lf->agent_name : "",
               lf->location ? lf->location : "");
    }

    Free_Eventinfo(lf);
    return failed;
}

int main(void)
{
    int failed = 0;

    memset(&Config, 0, sizeof(Config));
    Config.decoder_order_size = 8;
    strncpy(__shost, "managerhost", sizeof(__shost) - 1);
    c_time = time(NULL);

    printf("=== Issue 1668: agent vs log hostname ===\n");

    /* Agent-forwarded syslog with device hostname PRIMUS (#1668). */
    failed |= run_case(
        "agent + device hostname",
        "1:(client1) 10.1.2.3->/var/log/device.log:"
        "2019-02-14T02:54:39.696151+00:00 PRIMUS Config Process: Event: GOOD",
        "PRIMUS",
        "client1",
        "/var/log/device.log");

    /* Agent event with no parseable syslog hostname → fall back to agent. */
    failed |= run_case(
        "agent without device hostname",
        "1:(client1) 10.1.2.3->syscheck-registry:"
        "0:abcd:efgh /Registry/Key",
        "client1",
        "client1",
        "syscheck-registry");

    /* Local (non-agent) syslog keeps device hostname; no agent_name. */
    failed |= run_case(
        "local syslog device hostname",
        "1:/var/log/device.log:"
        "2019-02-14T02:54:39.696151+00:00 PRIMUS Config Process: Event: GOOD",
        "PRIMUS",
        NULL,
        "/var/log/device.log");

    failed |= run_accumulate_case();

    if (failed) {
        printf("\nFAIL: issue_1668_agent_hostname\n");
        return 1;
    }

    printf("\nPASS: issue_1668_agent_hostname\n");
    return 0;
}
