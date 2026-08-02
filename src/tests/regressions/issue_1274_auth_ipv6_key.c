/*
 * Regression test for issue #1274: ossec-authd -i with IPv6 agent keys.
 *
 * Build from src/:
 *   make -f tests/regressions/Makefile.1274
 *   ./issue_1274_auth_ipv6_key
 */

#include <stdio.h>
#include <string.h>
#include "addagent/manage_agents.h"

int main(void)
{
    const char *ipv6_key =
        "1041 ipv6test3 2001:db8::1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *any_key =
        "1042 ipv6test4 any 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *bad_name_key =
        "1043 bad:name 2001:db8::1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    if (!OS_IsValidAgentKey(ipv6_key)) {
        fprintf(stderr, "FAIL: IPv6 agent key should be valid\n");
        return (1);
    }

    if (!OS_IsValidAgentKey(any_key)) {
        fprintf(stderr, "FAIL: 'any' agent key should be valid\n");
        return (1);
    }

    if (OS_IsValidAgentKey(bad_name_key)) {
        fprintf(stderr, "FAIL: agent name with ':' should be rejected\n");
        return (1);
    }

    if (OS_IsValidName("2001:db8::1")) {
        fprintf(stderr, "FAIL: IPv6 address must not pass OS_IsValidName\n");
        return (1);
    }

    printf("PASS: issue #1274 auth IPv6 key validation\n");
    return (0);
}
