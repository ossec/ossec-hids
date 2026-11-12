/*
 * ANT-2026-QL3RS46Y: Windows registry checksum must use binary mode.
 *
 * Pre-fix, syscheck_sum.tmp was written with fopen(..., "w") and hashed
 * with OS_TEXT. On Windows the CRT treats 0x1a (Ctrl-Z) as EOF, so a value
 * name or string containing Ctrl-Z hid itself and every later value from the
 * MD5/SHA1. The local registry DB had the same text-mode risk.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ql3rs46y_winreg_ctrlz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

const char *__local_name = "issue-ql3rs46y-winreg-ctrlz";

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

/* Read path and return 1 if needle appears. Tries cwd (src/), repo root
 * (src/rel), and parent of src/. */
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

static void test_ctrlz_hides_trailing_bytes(void)
{
    const unsigned char full[] = "name=\x1aUpdater=evil\nLater=seen\n";
    const unsigned char cut[] = "name=";
    os_md5 md5_full, md5_cut;
    os_sha1 sha1_full, sha1_cut;
    FILE *fp;

    fp = fopen("queue/syscheck/ql3rs46y_full.tmp", "wb");
    CHECK(fp != NULL, "wrote full dump including Ctrl-Z");
    if (fp) {
        fwrite(full, 1, sizeof(full) - 1, fp);
        fclose(fp);
    }
    fp = fopen("queue/syscheck/ql3rs46y_cut.tmp", "wb");
    CHECK(fp != NULL, "wrote dump truncated at Ctrl-Z");
    if (fp) {
        fwrite(cut, 1, sizeof(cut) - 1, fp);
        fclose(fp);
    }

    CHECK(OS_MD5_SHA1_File("queue/syscheck/ql3rs46y_full.tmp",
                           md5_full, sha1_full, OS_BINARY) == 0,
          "binary hash of full dump");
    CHECK(OS_MD5_SHA1_File("queue/syscheck/ql3rs46y_cut.tmp",
                           md5_cut, sha1_cut, OS_BINARY) == 0,
          "binary hash of Ctrl-Z-truncated dump");
    CHECK(strcmp(md5_full, md5_cut) != 0,
          "bytes after Ctrl-Z change the checksum (must not be dropped)");
}

static void test_win_registry_uses_binary(void)
{
    const char *src = "syscheckd/win-registry.c";

    CHECK(source_has(src, "fopen(SYS_REG_TMP, \"wb\")"),
          "checksum temp is opened with \"wb\"");
    CHECK(source_has(src, "OS_MD5_SHA1_File(SYS_REG_TMP, mf_sum, sf_sum, OS_BINARY)"),
          "checksum temp is hashed with OS_BINARY");
    CHECK(source_has(src, "fopen(SYS_WIN_REG, \"r+b\")") ||
          source_has(src, "fopen(SYS_WIN_REG, \"w+b\")"),
          "registry DB is opened in binary mode (r+b or w+b)");
}

int main(void)
{
    printf("ANT-2026-QL3RS46Y winreg Ctrl-Z / binary-mode regression\n");

    if (system("mkdir -p queue/syscheck") != 0) {
        printf("  FAIL: mkdir queue/syscheck\n");
        return (1);
    }

    test_ctrlz_hides_trailing_bytes();
    test_win_registry_uses_binary();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
