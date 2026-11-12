/*
 * Regression: WoW64 System32 paths remap to Sysnative.
 *
 * Antigravity Defect 9.
 *
 * A 32-bit agent on 64-bit Windows redirects C:\Windows\System32 to
 * SysWOW64. os_win_sysnative_rewrite() turns a System32 path component
 * into Sysnative so syscheck watches native 64-bit binaries. Explicit
 * Sysnative / SysWOW64 paths are left alone.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_fim_wow64_sysnative
 *
 * Run:
 *   ./issue_fim_wow64_sysnative
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file_op.h"

const char *__local_name = "issue-fim-wow64-sysnative";

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void expect_rewrite(const char *in, const char *want, const char *msg)
{
    char out[512];
    int rc = os_win_sysnative_rewrite(in, out, sizeof(out));

    if (want == NULL) {
        CHECK(rc == 0, msg);
        return;
    }
    CHECK(rc == 1 && strcmp(out, want) == 0, msg);
    if (!(rc == 1 && strcmp(out, want) == 0)) {
        printf("        in='%s' got='%s' want='%s'\n", in, out, want);
    }
}

static void test_rewrite(void)
{
    expect_rewrite("C:/Windows/System32",
                   "C:/Windows/Sysnative",
                   "System32 directory remaps to Sysnative");
    expect_rewrite("C:/Windows/System32/drivers/etc",
                   "C:/Windows/Sysnative/drivers/etc",
                   "nested System32 path remaps");
    expect_rewrite("C:\\Windows\\System32\\at.exe",
                   "C:\\Windows\\Sysnative\\at.exe",
                   "backslash System32 path remaps");
    expect_rewrite("c:/windows/system32/net.exe",
                   "c:/windows/Sysnative/net.exe",
                   "remap is case-insensitive");
    expect_rewrite("C:/Windows/Sysnative/at.exe",
                   NULL,
                   "explicit Sysnative is unchanged");
    expect_rewrite("C:/Windows/SysWOW64/at.exe",
                   NULL,
                   "explicit SysWOW64 is unchanged");
    expect_rewrite("C:/Program Files/app",
                   NULL,
                   "paths without System32 are unchanged");
    expect_rewrite("C:/Windows/System32Extra/bin",
                   NULL,
                   "System32 prefix without separator is unchanged");
}

static int source_has(const char *rel, const char *needle)
{
    char path[512];
    FILE *fp = NULL;
    long len;
    char *buf;
    int found = 0;
    const char *prefixes[] = { "", "src/", "../", NULL };
    int i;

    for (i = 0; prefixes[i] != NULL; i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], rel);
        fp = fopen(path, "rb");
        if (fp) {
            break;
        }
    }
    if (!fp) {
        return (0);
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return (0);
    }
    len = ftell(fp);
    if (len < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return (0);
    }
    buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(fp);
        return (0);
    }
    if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return (0);
    }
    buf[len] = '\0';
    fclose(fp);
    found = (strstr(buf, needle) != NULL);
    free(buf);
    return (found);
}

static void test_config_wires_remap(void)
{
    CHECK(source_has("config/syscheck-config.c", "os_win_sysnative_rewrite"),
          "syscheck config remaps directories on WoW64");
    CHECK(source_has("config/syscheck-config.c", "os_win_is_wow64"),
          "syscheck config gates remap on WoW64");
}

int main(void)
{
    printf("issue_fim_wow64_sysnative\n");
    test_rewrite();
    test_config_wires_remap();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
