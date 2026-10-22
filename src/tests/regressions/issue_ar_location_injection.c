/*
 * ANT-2026-PMMTS4QR: spaces in lf->location must not become remoted AR
 * routing flags / command. AR_Forward() splits on the first space after
 * "(name) ", so only the manager-written "(name) ip" prefix may precede
 * the FFF flags.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "ar.h"

static int parse_ar_flags(char *hdr_mutable, int *out_flags)
{
    char *tmp;
    int flags = 0;

    /* Mirror remoted/ar-forward.c: after ')', skip " ip", then read FFF. */
    tmp = strchr(hdr_mutable, ')');
    if (!tmp) {
        return -1;
    }
    tmp += 2;
    tmp = strchr(tmp, ' ');
    if (!tmp) {
        return -1;
    }
    tmp++;

    if (*tmp == ALL_AGENTS_C) {
        flags |= ALL_AGENTS;
    }
    tmp++;
    if (*tmp == REMOTE_AGENT_C) {
        flags |= REMOTE_AGENT;
    } else if (*tmp == NO_AR_C) {
        flags |= NO_AR_MSG;
    }
    tmp++;
    if (*tmp == SPECIFIC_AGENT_C) {
        flags |= SPECIFIC_AGENT;
    }

    *out_flags = flags;
    return 0;
}

static int expect_flags(const char *label, const char *location,
                        char f_all, char f_remote, char f_specific,
                        int want_flags)
{
    char *hdr = NULL;
    char *copy;
    int flags = 0;
    int rc;

    printf("--- %s ---\n", label);
    printf("  location: %s\n", location);

    if (OS_AR_FormatRemoteHdr(location, f_all, f_remote, f_specific, &hdr) != 0) {
        printf("  FAIL: OS_AR_FormatRemoteHdr rejected location\n");
        return 1;
    }
    printf("  hdr: %s\n", hdr);

    copy = strdup(hdr);
    if (!copy) {
        free(hdr);
        printf("  FAIL: strdup\n");
        return 1;
    }

    rc = parse_ar_flags(copy, &flags);
    free(copy);
    free(hdr);

    if (rc != 0) {
        printf("  FAIL: could not parse flags from header\n");
        return 1;
    }

    if (flags != want_flags) {
        printf("  FAIL: flags=0%o want=0%o (injected location text became routing)\n",
               flags, want_flags);
        return 1;
    }

    printf("  ok: flags=0%o\n", flags);
    return 0;
}

int main(void)
{
    int failed = 0;
    /* Configured response is local (NRN): only the reporting agent. */
    const int want_local = REMOTE_AGENT;
    /* Injected "ANN 000 host-deny..." after |x in the location. */
    const char *injected =
        "(web01) any->/var/log/messages|x ANN 000 host-deny600 - 127.0.0.1 0 0";
    const char *benign =
        "(web01) any->/var/log/messages|x";
    const char *cmd_loc = "df -P";

    printf("=== ANT-2026-PMMTS4QR: AR location must not inject remoted flags ===\n");

    failed |= expect_flags("benign agent location", benign,
                           NONE_C, REMOTE_AGENT_C, NONE_C, want_local);

    failed |= expect_flags("injected spaces after ->", injected,
                           NONE_C, REMOTE_AGENT_C, NONE_C, want_local);

    /* Manager-local events: source must be constant [], not free text. */
    failed |= expect_flags("command monitor location with space", cmd_loc,
                           NONE_C, REMOTE_AGENT_C, NONE_C, want_local);

    /* Agent-shaped location without "->" is invalid for remoted. */
    {
        char *hdr = NULL;
        printf("--- agent location missing -> ---\n");
        if (OS_AR_FormatRemoteHdr("(web01) any", NONE_C, REMOTE_AGENT_C, NONE_C,
                                  &hdr) == 0) {
            printf("  FAIL: accepted location without ->\n");
            free(hdr);
            failed = 1;
        } else {
            printf("  ok: rejected\n");
        }
    }

    if (failed) {
        printf("\nFAIL: issue_ar_location_injection\n");
        return 1;
    }

    printf("\nPASS: issue_ar_location_injection\n");
    return 0;
}
