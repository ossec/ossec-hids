/*
 * ANT-2026-RXUWSL9Z: Splunk/CEF serialisers must escape attacker-controlled
 * field text so quotes / '=' cannot inject extra SIEM key/value pairs.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_rxuwsl9z_csyslog_escape
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "os_csyslogd/csyslogd.h"

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

/* Count unescaped key="value" pairs the way the Anthropic repro does. */
static int count_quoted_pairs(const char *msg)
{
    int n = 0;
    const char *p = msg;

    while ((p = strstr(p, "=\"")) != NULL) {
        const char *q = p + 2;
        while (*q) {
            if (*q == '\\' && q[1] != '\0') {
                q += 2;
                continue;
            }
            if (*q == '"') {
                n++;
                p = q + 1;
                break;
            }
            q++;
        }
        if (!*q) {
            break;
        }
    }
    return (n);
}

static void check_splunk_quote_injection(void)
{
    const char *user =
        "bob\",file=\"/etc/shadow\",md5_new=\"d41d8cd98f00b204e9800998ecf8427e";
    char record[512];
    char *esc;
    int pairs;

    printf("--- Splunk acct= quote injection ---\n");
    esc = splunkescape(user);
    snprintf(record, sizeof(record), "acct=\"%s\", message=\"x\"", esc);
    pairs = count_quoted_pairs(record);
    CHECK(pairs == 2,
          "injected quotes do not create extra key=\"value\" pairs");
    CHECK(strchr(esc, '"') == NULL,
          "splunkescape removes double quotes");
    splunkescape(NULL);
}

static void check_splunk_backslash(void)
{
    char *esc;

    printf("--- Splunk trailing backslash ---\n");
    esc = splunkescape("bob\\");
    CHECK(esc != NULL && strcmp(esc, "bob\\\\") == 0,
          "trailing backslash is doubled");
    splunkescape(NULL);
}

static void check_splunk_newline(void)
{
    char *esc;

    printf("--- Splunk newline line-break ---\n");
    esc = splunkescape("bob\nfile=/etc/shadow");
    CHECK(esc != NULL && strchr(esc, '\n') == NULL && strchr(esc, '\r') == NULL,
          "CR/LF are removed from Splunk values");
    CHECK(esc != NULL && strcmp(esc, "bob file=/etc/shadow") == 0,
          "CR/LF become spaces (single value)");
    splunkescape(NULL);
}

static void check_cef_src_injection(void)
{
    const char *srcip = "10.1.1.3 dvc=dc01 outcome=success";
    char *esc;

    printf("--- CEF src= extension injection ---\n");
    esc = cefescape(srcip, 0);
    CHECK(esc != NULL && strstr(esc, "dvc\\=") != NULL,
          "cefescape escapes '=' in address-like values");
    CHECK(strstr(esc, " dvc=") == NULL,
          "raw ' dvc=' does not remain after escape");
    cefescape(NULL, 0);
}

int main(void)
{
    failures = 0;

    printf("=== ANT-2026-RXUWSL9Z: csyslog Splunk/CEF field escape ===\n");

    check_splunk_quote_injection();
    check_splunk_backslash();
    check_splunk_newline();
    check_cef_src_injection();

    if (failures) {
        printf("\nFAIL: issue_rxuwsl9z_csyslog_escape (%d)\n", failures);
        return (1);
    }

    printf("\nPASS: issue_rxuwsl9z_csyslog_escape\n");
    return (0);
}
