/*
 * Regression: IPv6 agent disconnect location split at ':'
 *
 * ANT-2026-U64THXI1 / CWE-140
 *
 * monitor_agents() queued "<name>-<ip>->ossec-monitord". The queue message
 * is "id:location:message", and OS_CleanMSG_ex() ends the location at the
 * first ':' unless the location is "(name) ip->...". An IPv6 address was
 * cut inside the address, so the log no longer started with "ossec: " and
 * rule 504 did not fire.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_u64thxi1_ipv6_disconnect
 *
 * Run:
 *   ./issue_u64thxi1_ipv6_disconnect
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
#include "error_messages/error_messages.h"

_Config Config;
__thread time_t c_time;
__thread int __crt_hour;
__thread int __crt_wday;
char __shost[512];
OSDecoderInfo *NULL_Decoder = NULL;
int alert_only = 1;

void monitor_disconnect_location(const char *agent, const char *prog,
                                 char *out, size_t outsz);

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static void check_agent(const char *agent, const char *name, const char *ip,
                        const char *location)
{
    Eventinfo *lf;
    char loc[OS_SIZE_1024];
    char msg[OS_SIZE_1024 + OS_SIZE_1024 + 8];
    char body[OS_SIZE_1024];

    printf("--- %s ---\n", agent);
    monitor_disconnect_location(agent, "ossec-monitord", loc, sizeof(loc));
    expect(strcmp(loc, location) == 0, "disconnect location");
    if (strcmp(loc, location) != 0) {
        printf("        got '%s'\n", loc);
    }

    snprintf(body, sizeof(body), OS_AG_DISCON, agent);
    snprintf(msg, sizeof(msg), "1:%s:%s", loc, body);

    lf = calloc(1, sizeof(*lf));
    if (lf == NULL) {
        expect(0, "calloc Eventinfo");
        return;
    }
    Zero_Eventinfo(lf);
    expect(OS_CleanMSG_ex(msg, lf, time(NULL), 0) == 0, "OS_CleanMSG_ex");
    expect(lf->location && strcmp(lf->location, location) == 0,
           "parsed location keeps the address");
    expect(lf->log && strncmp(lf->log, "ossec: ", 7) == 0,
           "log still starts with ossec:");
    if (name) {
        expect(lf->agent_name && strcmp(lf->agent_name, name) == 0,
               "agent name");
    } else {
        expect(lf->agent_name == NULL, "no agent name");
    }
    if (ip && lf->location) {
        expect(strstr(lf->location, ip) != NULL, "address is intact");
    }
    Free_Eventinfo(lf);
}

int main(void)
{
    check_agent("web02-2001:db8::7", "web02", "2001:db8::7",
                "(web02) 2001:db8::7->ossec-monitord");
    check_agent("web-02-2001:db8::7", "web-02", "2001:db8::7",
                "(web-02) 2001:db8::7->ossec-monitord");
    check_agent("web01-192.0.2.7", "web01", "192.0.2.7",
                "(web01) 192.0.2.7->ossec-monitord");
    check_agent("web02-any", "web02", "any",
                "(web02) any->ossec-monitord");
    check_agent("web02", NULL, NULL, "ossec-monitord");

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
