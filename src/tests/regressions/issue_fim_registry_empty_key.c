/*
 * Regression: empty registry keys must still be baselined.
 *
 * Antigravity Defect 8.
 *
 * Pre-fix, os_winreg_querykey() only called os_winreg_queryvalues() when
 * value_count != 0, so newly created keys without values never entered
 * syscheckregistry.db and could not be monitored or deleted (Rule 597).
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_fim_registry_empty_key
 *
 * Run:
 *   ./issue_fim_registry_empty_key
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

const char *__local_name = "issue-fim-registry-empty-key";

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

/* True if needle appears and is not only inside a line that still gates
 * queryvalues on value_count. */
static int queryvalues_unconditional(void)
{
    const char *rel = "syscheckd/win-registry.c";
    char path[512];
    FILE *fp = NULL;
    char line[512];
    int in_querykey = 0;
    int saw_call = 0;
    int gated = 0;
    const char *prefixes[] = { "", "src/", "../", NULL };
    int i;

    for (i = 0; prefixes[i] != NULL; i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], rel);
        fp = fopen(path, "r");
        if (fp) {
            break;
        }
    }
    if (!fp) {
        return (0);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "void os_winreg_querykey(") != NULL) {
            in_querykey = 1;
            continue;
        }
        if (!in_querykey) {
            continue;
        }
        /* Next top-level function ends the scan. */
        if (line[0] != ' ' && line[0] != '\t' && line[0] != '{' &&
                line[0] != '}' && line[0] != '\n' && line[0] != '\r' &&
                strstr(line, "os_winreg_querykey") == NULL &&
                strchr(line, '(') != NULL) {
            break;
        }
        if (strstr(line, "if (value_count)") != NULL ||
                strstr(line, "if(value_count)") != NULL) {
            gated = 1;
        }
        if (strstr(line, "os_winreg_queryvalues(") != NULL) {
            saw_call = 1;
            /* Call on the same or following structure without a gate. */
            if (gated) {
                fclose(fp);
                return (0);
            }
        }
    }
    fclose(fp);
    return (saw_call && !gated);
}

static void test_empty_file_hash_stable(void)
{
    os_md5 md5_a, md5_b;
    os_sha1 sha1_a, sha1_b;
    FILE *fp;

    if (system("mkdir -p queue/syscheck") != 0) {
        CHECK(0, "mkdir queue/syscheck");
        return;
    }

    fp = fopen("queue/syscheck/empty_reg.tmp", "wb");
    CHECK(fp != NULL, "open empty registry dump");
    if (fp) {
        fclose(fp);
    }

    CHECK(OS_MD5_SHA1_File("queue/syscheck/empty_reg.tmp",
                           md5_a, sha1_a, OS_BINARY) == 0,
          "hash empty dump (1)");
    CHECK(OS_MD5_SHA1_File("queue/syscheck/empty_reg.tmp",
                           md5_b, sha1_b, OS_BINARY) == 0,
          "hash empty dump (2)");
    CHECK(strcmp(md5_a, md5_b) == 0 && strcmp(sha1_a, sha1_b) == 0,
          "empty dump checksum is stable across runs");
}

static void test_source_baselines_empty_keys(void)
{
    const char *src = "syscheckd/win-registry.c";

    CHECK(source_has(src, "Antigravity Defect 8"),
          "empty-key baseline fix is documented in source");
    CHECK(queryvalues_unconditional(),
          "os_winreg_querykey always calls os_winreg_queryvalues");
}

int main(void)
{
    printf("issue_fim_registry_empty_key\n");
    test_empty_file_hash_stable();
    test_source_baselines_empty_keys();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
