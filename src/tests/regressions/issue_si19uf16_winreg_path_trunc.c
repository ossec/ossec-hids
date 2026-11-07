/*
 * ANT-2026-SI19UF16: refuse truncated Windows registry subkey paths.
 *
 * Pre-fix, os_winreg_querykey() opened whatever snprintf(MAX_KEY) produced.
 * When the parent path was already 2047 characters, the "subkey" path was the
 * parent again and the walk recursed until the stack ran out.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_si19uf16_winreg_path_trunc
 */

#include <stdio.h>
#include <string.h>

#include "syscheckd/winreg_path.h"

const char *__local_name = "issue-si19uf16-winreg-path-trunc";

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void fill(char *buf, size_t n, char c)
{
    memset(buf, c, n);
    buf[n] = '\0';
}

static void test_truncation_refused(void)
{
    char parent[OS_WINREG_MAX_KEY];
    char full_parent[OS_WINREG_MAX_KEY];
    char new_key[OS_WINREG_MAX_KEY + 2];
    char new_key_full[OS_WINREG_MAX_KEY + 2];
    int rc;

    /* Parent open-path is already MAX_KEY-1 characters: adding "\x" cannot fit. */
    fill(parent, OS_WINREG_MAX_KEY - 1, 'a');
    fill(full_parent, OS_WINREG_MAX_KEY - 1, 'H');

    rc = os_winreg_build_subkey_paths(new_key, new_key_full, OS_WINREG_MAX_KEY,
                                      parent, full_parent, "x");
    CHECK(rc == -1,
          "2047-char parent + subkey is refused");

    /* Truncation without a check would reopen the parent. */
    CHECK(strncmp(new_key, parent, OS_WINREG_MAX_KEY - 1) == 0,
          "truncated open path matches the parent (bug trigger)");
}

static void test_short_paths_ok(void)
{
    char new_key[OS_WINREG_MAX_KEY + 2];
    char new_key_full[OS_WINREG_MAX_KEY + 2];
    int rc;

    rc = os_winreg_build_subkey_paths(new_key, new_key_full, OS_WINREG_MAX_KEY,
                                      "Software\\Foo",
                                      "HKEY_LOCAL_MACHINE\\Software\\Foo",
                                      "Bar");
    CHECK(rc == 0, "short subkey paths are accepted");
    CHECK(strcmp(new_key, "Software\\Foo\\Bar") == 0,
          "open path is parent\\subkey");
    CHECK(strcmp(new_key_full,
                 "HKEY_LOCAL_MACHINE\\Software\\Foo\\Bar") == 0,
          "full path keeps the HKEY prefix");

    rc = os_winreg_build_subkey_paths(new_key, new_key_full, OS_WINREG_MAX_KEY,
                                      NULL,
                                      "HKEY_LOCAL_MACHINE\\Software",
                                      "Foo");
    CHECK(rc == 0, "root-level subkey (no p_key) is accepted");
    CHECK(strcmp(new_key, "Foo") == 0, "root-level open path is the subkey");
}

static void test_full_name_overflows_first(void)
{
    char parent[OS_WINREG_MAX_KEY];
    char full_parent[OS_WINREG_MAX_KEY];
    char new_key[OS_WINREG_MAX_KEY + 2];
    char new_key_full[OS_WINREG_MAX_KEY + 2];
    int rc;

    /* Open path still fits; full name with HKEY_ prefix does not. */
    fill(parent, 100, 'a');
    fill(full_parent, OS_WINREG_MAX_KEY - 1, 'H');

    rc = os_winreg_build_subkey_paths(new_key, new_key_full, OS_WINREG_MAX_KEY,
                                      parent, full_parent, "x");
    CHECK(rc == -1,
          "full-name overflow alone is refused");
}

int main(void)
{
    printf("ANT-2026-SI19UF16 winreg path truncation regression\n");
    test_truncation_refused();
    test_short_paths_ok();
    test_full_name_overflows_first();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
