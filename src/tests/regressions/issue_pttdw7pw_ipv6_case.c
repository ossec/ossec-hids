/*
 * Regression: ossec-execd treats two IPv6 spellings as two blocks
 *
 * ANT-2026-PTTDW7PW / CWE-178
 *
 * ExecdStart() compares the srcip text with strcmp(). 2001:DB8::7 and
 * 2001:db8::7 are one address to pf, so the first timeout deletes the
 * table entry while execd still counts the other spelling as blocked.
 * A literal address must have one spelling before it is compared,
 * stored, or handed to the script. Host names, "-", CIDR, and a
 * leading "!" stay as written.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_pttdw7pw_ipv6_case
 *
 * Run:
 *   ./issue_pttdw7pw_ipv6_case
 */

#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "os_execd/execd.h"

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

static void same_spelling(const char *a, const char *b, const char *want, const char *msg)
{
    char ca[64];
    char cb[64];
    int ra;
    int rb;

    ca[0] = '\0';
    cb[0] = '\0';
    ra = CanonicalIP(a, ca, sizeof(ca));
    rb = CanonicalIP(b, cb, sizeof(cb));
    expect(ra == 1 && rb == 1 && strcmp(ca, cb) == 0 && strcmp(ca, want) == 0, msg);
}

int main(void)
{
    char dst[64];

    printf("execd IPv6 address spelling\n");

    same_spelling("2001:DB8::7", "2001:db8::7", "2001:db8::7",
                  "IPv6 letter case is one spelling");
    same_spelling("::ffff:192.0.2.1", "192.0.2.1", "192.0.2.1",
                  "an IPv4-mapped address is the IPv4 address");
    same_spelling("192.0.2.1", "192.0.2.1", "192.0.2.1",
                  "an IPv4 address stays dotted decimal");

    expect(CanonicalIP("mail.example", dst, sizeof(dst)) == 0,
           "a host name is left unchanged");
    expect(CanonicalIP("-", dst, sizeof(dst)) == 0,
           "a dash user placeholder is left unchanged");
    expect(CanonicalIP("2001:db8::/64", dst, sizeof(dst)) == 0,
           "a CIDR prefix is left unchanged");
    expect(CanonicalIP("!192.0.2.1", dst, sizeof(dst)) == 0,
           "a negated address is left unchanged");

    if (failures) {
        printf("FAIL: %d IPv6 spelling check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
