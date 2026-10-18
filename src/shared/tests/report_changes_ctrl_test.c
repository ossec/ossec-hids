/*
 * #2359 — report_changes framing vs remove_control_characters (CVE-2020-8445).
 *
 * Syscheck emits "checksum /path\n<diff>". DecodeSyscheck splits on that '\n'.
 * OS_CleanMSG must preserve '\\n' only for exact syscheck locations
 * (OS_IsSyscheckLocation) while still stripping other C0/DEL.
 *
 * From src/ after shared.a is built:
 *   make -C shared/tests report_changes_ctrl_test
 *   ./shared/tests/report_changes_ctrl_test
 */

#include <stdio.h>
#include <string.h>

#include "shared.h"

static int failures;

static void expect_true(const char *name, int cond)
{
    if (!cond) {
        printf("FAIL %s\n", name);
        failures++;
    } else {
        printf("OK   %s\n", name);
    }
}

/* DecodeSyscheck: first space separates sum from name; '\n' separates name/diff. */
static int sk_split(char *log, char **name_out, char **diff_out)
{
    char *name;
    char *diff;

    name = strchr(log, ' ');
    if (!name) {
        return -1;
    }
    *name = '\0';
    name++;

    diff = strchr(name, '\n');
    if (diff) {
        *diff = '\0';
        diff++;
    }

    *name_out = name;
    *diff_out = diff;
    return 0;
}

static void test_syscheck_location_gate(void)
{
    expect_true("local syscheck",
                OS_IsSyscheckLocation("syscheck") == 1);
    expect_true("local syscheck-registry",
                OS_IsSyscheckLocation("syscheck-registry") == 1);
    expect_true("agent syscheck",
                OS_IsSyscheckLocation("(client1) 10.1.2.3->syscheck") == 1);
    expect_true("agent syscheck-registry",
                OS_IsSyscheckLocation("(client1) 10.1.2.3->syscheck-registry") == 1);

    expect_true("null location", OS_IsSyscheckLocation(NULL) == 0);
    expect_true("empty location", OS_IsSyscheckLocation("") == 0);
    expect_true("syslog path",
                OS_IsSyscheckLocation("/var/log/secure") == 0);
    expect_true("agent syslog",
                OS_IsSyscheckLocation("(client1) 10.1.2.3->/var/log/secure") == 0);
    expect_true("substring in agent name is not enough",
                OS_IsSyscheckLocation("(syscheck) 10.1.2.3->/var/log/secure") == 0);
    expect_true("arrow inside agent name uses last arrow",
                OS_IsSyscheckLocation("(evil->syscheck) 10.1.2.3->/var/log/x") == 0);
    expect_true("arrow inside agent name still finds real module",
                OS_IsSyscheckLocation("(evil->x) 10.1.2.3->syscheck") == 1);
    expect_true("syscheck prefix alone is not enough",
                OS_IsSyscheckLocation("syscheck-extra") == 0);
}

static void test_syscheck_preserve_nl(void)
{
    char body[] =
        "0:0:0:0:d41d8cd98f00b204e9800998ecf8427e:"
        "da39a3ee5e6b4b0d3255bfef95601890afd80709:"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "/etc/hosts\n"
        "212c212\n"
        "< old line\n"
        "---\n"
        "> new line";
    char *name = NULL;
    char *diff = NULL;

    remove_control_characters_ex(body, OS_IsSyscheckLocation("syscheck"));

    expect_true("syscheck preserve: '\\n' kept",
                strchr(body, '\n') != NULL);

    if (sk_split(body, &name, &diff) != 0) {
        expect_true("checksum/path space present", 0);
        return;
    }

    expect_true("filename is exact path",
                name && strcmp(name, "/etc/hosts") == 0);
    expect_true("diff payload retained after separator",
                diff && strstr(diff, "212c212") != NULL);

    if (name && strcmp(name, "/etc/hosts") != 0) {
        printf("     got filename '%s'\n", name);
    }
}

static void test_default_still_strips_nl(void)
{
    char body[] = "hello\nworld\x07";

    remove_control_characters(body);
    expect_true("default strip removes '\\n'", strchr(body, '\n') == NULL);
    expect_true("default strip removes bell", strchr(body, '\x07') == NULL);
    expect_true("default strip keeps text", strcmp(body, "helloworld") == 0);
}

static void test_non_syscheck_location_strips_nl(void)
{
    char body[] = "line1\nline2";

    remove_control_characters_ex(body,
                                 OS_IsSyscheckLocation("/var/log/messages"));
    expect_true("non-syscheck location strips '\\n'",
                strchr(body, '\n') == NULL);
    expect_true("non-syscheck text kept", strcmp(body, "line1line2") == 0);
}

static void test_preserve_still_strips_other_controls(void)
{
    char body[] = "sum /path\x07\x1B\trest\nmore";

    remove_control_characters_ex(body, 1);
    expect_true("preserve: bell stripped", strchr(body, '\x07') == NULL);
    expect_true("preserve: ESC stripped", strchr(body, '\x1B') == NULL);
    expect_true("preserve: tab kept", strchr(body, '\t') != NULL);
    expect_true("preserve: newline kept", strchr(body, '\n') != NULL);
    expect_true("preserve: path text retained", strstr(body, "/path") != NULL);
}

static void test_plain_syscheck_unchanged(void)
{
    char body[] =
        "0:0:0:0:d41d8cd98f00b204e9800998ecf8427e:"
        "da39a3ee5e6b4b0d3255bfef95601890afd80709:"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "/etc/passwd";
    char *name = NULL;
    char *diff = NULL;

    remove_control_characters_ex(body, 1);
    expect_true("plain syscheck splits", sk_split(body, &name, &diff) == 0);
    expect_true("plain filename", name && strcmp(name, "/etc/passwd") == 0);
    expect_true("plain has no diff", diff == NULL);
}

int main(void)
{
    failures = 0;

    printf("=== report_changes_ctrl_test (#2359) ===\n");
    test_syscheck_location_gate();
    test_syscheck_preserve_nl();
    test_default_still_strips_nl();
    test_non_syscheck_location_strips_nl();
    test_preserve_still_strips_other_controls();
    test_plain_syscheck_unchanged();

    if (failures) {
        printf("FAIL: report_changes_ctrl_test (%d)\n", failures);
        return 1;
    }
    printf("PASS: report_changes_ctrl_test\n");
    return 0;
}
