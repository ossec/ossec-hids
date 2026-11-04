/*
 * ANT-2026-9UQVLIX8: interface names fed to ifconfig via system() must be
 * a single shell-quoted word (and not start with '-').
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_9uqvlix8_ifconfig_inject
 */

#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <net/if.h>
#endif

#include "shared.h"
#include "rootcheck.h"

#ifndef WIN32

/* Linked via check_rc_if.c; unused by this unit test. */
int notify_rk(int rk_type, const char *msg)
{
    (void)rk_type;
    (void)msg;
    return (0);
}

int main(void)
{
    char out[(IFNAMSIZ * 4) + 3];
    char cmd[OS_SIZE_1024 + 1];
    int failed = 0;

    printf("=== ANT-2026-9UQVLIX8: ifconfig interface shell quoting ===\n");

    if (rk_shell_quote_ifname("lo:;id>/tmp/p", out, sizeof(out)) != 1) {
        printf("  FAIL: refused injectable alias label\n");
        failed = 1;
    } else if (strcmp(out, "'lo:;id>/tmp/p'") != 0) {
        printf("  FAIL: quote result '%s'\n", out);
        failed = 1;
    } else {
        snprintf(cmd, sizeof(cmd), "ifconfig %s | grep PROMISC", out);
        if (strstr(cmd, "ifconfig lo:") != NULL &&
                strstr(cmd, "'lo:;id>/tmp/p'") == NULL) {
            printf("  FAIL: metacharacters reached the shell unquoted\n");
            failed = 1;
        } else {
            printf("  ok: injectable label is one single-quoted word\n");
        }
    }

    if (rk_shell_quote_ifname("eth0", out, sizeof(out)) != 1 ||
            strcmp(out, "'eth0'") != 0) {
        printf("  FAIL: plain eth0 quoting ('%s')\n", out);
        failed = 1;
    } else {
        printf("  ok: plain interface name quoted\n");
    }

    if (rk_shell_quote_ifname("a'b", out, sizeof(out)) != 1 ||
            strcmp(out, "'a'\\''b'") != 0) {
        printf("  FAIL: embedded quote escaping ('%s')\n", out);
        failed = 1;
    } else {
        printf("  ok: embedded single quote escaped\n");
    }

    if (rk_shell_quote_ifname("-i", out, sizeof(out)) != 0 ||
            rk_shell_quote_ifname("", out, sizeof(out)) != 0) {
        printf("  FAIL: empty / leading-dash names must be refused\n");
        failed = 1;
    } else {
        printf("  ok: empty and leading-dash names refused\n");
    }

    if (failed) {
        printf("\nFAIL: issue_9uqvlix8_ifconfig_inject\n");
        return (1);
    }
    printf("\nPASS: issue_9uqvlix8_ifconfig_inject\n");
    return (0);
}

#else

int main(void)
{
    printf("SKIP: ANT-2026-9UQVLIX8 is Unix-only\n");
    return (0);
}

#endif
