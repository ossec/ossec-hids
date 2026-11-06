/*
 * Regression: ossec-execd splits a syscheck filename on an escaped space
 *
 * ANT-2026-Z12L5BYR / CWE-88
 *
 * OS_Exec() protects a file name with os_shell_escape(), but ExecdStart()
 * cuts the request at every space and passes the pieces to execv(). A
 * space in a monitored name therefore becomes an extra argument of the
 * root response script. A space with a backslash before it must stay
 * inside the name. A backslash that is itself escaped does not protect
 * the following space.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_z12l5byr_filename_split
 *
 * Run:
 *   ./issue_z12l5byr_filename_split
 */

#include <stdio.h>
#include <string.h>

#include "shared.h"

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

/* Split the way ExecdStart() does and return the number of pieces. */
static int split_request(char *request, char **out, int max)
{
    int n = 0;
    char *next;

    while (request && n < max) {
        next = os_shell_escape_strchr(request, ' ');
        if (next) {
            *next = '\0';
            next++;
        }
        out[n++] = request;
        request = next;
    }
    return n;
}

static void expect_one_name(const char *raw, const char *msg)
{
    char request[256];
    char *args[8];
    char *escaped;
    int n;
    int wrote;

    escaped = os_shell_escape(raw);
    expect(escaped != NULL, "os_shell_escape returned a name");
    if (!escaped) {
        return;
    }

    wrote = snprintf(request, sizeof(request), "syscheck %s", escaped);
    expect(wrote > 0 && (size_t)wrote < sizeof(request), "the request fits");
    n = split_request(request, args, 8);
    expect(n == 2 && strcmp(args[0], "syscheck") == 0 &&
           strcmp(args[1], escaped) == 0, msg);
    free(escaped);
}

int main(void)
{
    char request[128];
    char *args[8];
    int n;

    printf("execd escaped filename split\n");

    expect_one_name("/srv/uploads/x /etc/shadow",
                    "an escaped space stays inside the file name");
    expect_one_name("/tmp/y --delete -f",
                    "an escaped space does not start an option");
    expect_one_name("/tmp/x\\ y\\",
                    "a name with a backslash and a space stays one argument");

    /* A backslash that is not before the space still ends the field.
     * C:\\x is one argument; the following name is the next.
     */
    snprintf(request, sizeof(request), "- (a) 1.2.3.4->C:\\x /tmp/f");
    n = split_request(request, args, 8);
    expect(n == 4 &&
           strcmp(args[0], "-") == 0 &&
           strcmp(args[1], "(a)") == 0 &&
           strcmp(args[2], "1.2.3.4->C:\\x") == 0 &&
           strcmp(args[3], "/tmp/f") == 0,
           "a plain request still splits on unescaped spaces");

    /* \\ then a space: the backslash is escaped, so the space separates. */
    snprintf(request, sizeof(request), "syscheck /tmp/x\\\\ next");
    n = split_request(request, args, 8);
    expect(n == 3 &&
           strcmp(args[0], "syscheck") == 0 &&
           strcmp(args[1], "/tmp/x\\\\") == 0 &&
           strcmp(args[2], "next") == 0,
           "an escaped backslash leaves the following space as a separator");

    if (failures) {
        printf("FAIL: %d filename split check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
