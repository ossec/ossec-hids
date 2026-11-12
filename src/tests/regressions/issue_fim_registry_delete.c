/*
 * Regression: Windows registry FIM must emit -1 for deleted keys.
 *
 * Antigravity Defect 7 / Rule 597 dead code.
 *
 * Pre-fix, win-registry.c hashed live keys into syscheckregistry.db but
 * never compared the DB against the registry. RegOpenKeyEx FILE_NOT_FOUND
 * only logged a debug line, so Rule 597 (syscheck-registry + sid 553) never
 * fired. Periodic reconcile must notify "-1 <tagged-key>" and drop the row.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_fim_registry_delete
 *
 * Run:
 *   ./issue_fim_registry_delete
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

const char *__local_name = "issue-fim-registry-delete";

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

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

/* Mirror of os_winreg_under_root for Linux unit coverage. */
static int under_root(const char *full_path, const char *root)
{
    size_t len;

    if (full_path == NULL || root == NULL || root[0] == '\0') {
        return (0);
    }
    len = strlen(root);
    while (len > 1 && root[len - 1] == '\\') {
        len--;
    }
    if (strncasecmp(full_path, root, len) != 0) {
        return (0);
    }
    return (full_path[len] == '\0' || full_path[len] == '\\');
}

static void test_under_root(void)
{
    CHECK(under_root("HKEY_LOCAL_MACHINE\\Software\\X",
                     "HKEY_LOCAL_MACHINE\\Software") != 0,
          "child key is under configured root");
    CHECK(under_root("HKEY_LOCAL_MACHINE\\Software",
                     "HKEY_LOCAL_MACHINE\\Software\\") != 0,
          "exact root matches with trailing slash stripped");
    CHECK(under_root("HKEY_LOCAL_MACHINE\\SoftwareX",
                     "HKEY_LOCAL_MACHINE\\Software") == 0,
          "prefix without separator is not under root");
    CHECK(under_root("hkey_local_machine\\software\\x",
                     "HKEY_LOCAL_MACHINE\\Software") != 0,
          "registry path match is case-insensitive");
}

static void test_source_reconciles_deletes(void)
{
    const char *src = "syscheckd/win-registry.c";

    CHECK(source_has(src, "os_winreg_reconcile_missing"),
          "registry check reconciles missing DB keys");
    CHECK(source_has(src, "os_winreg_seen_mark"),
          "hashed keys are marked seen for the scan");
    CHECK(source_has(src, "snprintf(del_msg, sizeof(del_msg), \"-1 %s\", sp + 1)"),
          "deletion notify uses the -1 syscheck marker");
    CHECK(source_has(src, "fopen(SYS_WIN_REG, \"r+b\")"),
          "registry DB is reopened with r+b across restarts");
    CHECK(source_has(src, "notify_registry(del_msg, 1)"),
          "deletion is sent on the syscheck-registry queue");
}

int main(void)
{
    printf("issue_fim_registry_delete\n");
    test_under_root();
    test_source_reconciles_deletes();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
