/*
 * ANT-2026-3VN001L2: retire <syscheck><prefilter_cmd>.
 *
 * The historical sink was OS_MD5_SHA1_File()'s unquoted popen("%s %s",
 * prefilter_cmd, fname). A local user who can create a monitored file whose
 * name contains shell metacharacters could run commands as root whenever
 * prefilter_cmd was set. OSSEC retires the option entirely 
 * no popen path; config warns and continues if the tag is still present.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_3vn001l2_prefilter_retire
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "shared.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

static int failed;

static void expect(int ok, const char *msg)
{
    if (ok) {
        printf("  ok: %s\n", msg);
        return;
    }
    printf("  FAIL: %s\n", msg);
    failed = 1;
}

static FILE *open_src(const char *rel)
{
    FILE *fp = fopen(rel, "r");
    char alt[512];

    if (fp) {
        return fp;
    }
    snprintf(alt, sizeof(alt), "../%s", rel);
    return fopen(alt, "r");
}

static int file_contains(const char *rel, const char *needle)
{
    FILE *fp;
    char line[512];
    int found = 0;

    fp = open_src(rel);
    if (!fp) {
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, needle)) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

static int md5_has_popen(void)
{
    return file_contains("os_crypto/md5_sha1/md5_sha1_op.c", "popen");
}

static int config_stores_prefilter(void)
{
    FILE *fp;
    char line[512];
    int found = 0;

    fp = open_src("config/syscheck-config.c");
    if (!fp) {
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "prefilter_cmd")) {
            continue;
        }
        /* Retirement path mentions the tag name; ignore warn/log lines. */
        if (strstr(line, "retired") || strstr(line, "deprecated") ||
            strstr(line, "no longer") || strstr(line, "mwarn") ||
            strstr(line, "verbose") || strstr(line, "merror") ||
            strstr(line, "xml_prefilter") || strstr(line, "strcmp")) {
            continue;
        }
        if (strstr(line, "syscheck->prefilter_cmd") ||
            strstr(line, "os_calloc") || strstr(line, "strncpy")) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

int main(void)
{
    char workdir[] = "/tmp/ossec-3vn001l2-XXXXXX";
    char path[512];
    char marker[512];
    os_md5 md5;
    os_sha1 sha1;
    FILE *fp;
    int rc;
    int popen_hit;
    int store_hit;
    int warn_hit;

    failed = 0;
    printf("=== ANT-2026-3VN001L2: retire prefilter_cmd ===\n");

    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return 1;
    }

    popen_hit = md5_has_popen();
    expect(popen_hit == 0, "md5_sha1_op.c has no popen() prefilter sink");

    store_hit = config_stores_prefilter();
    expect(store_hit == 0, "syscheck-config.c does not store prefilter_cmd");

    warn_hit = file_contains("config/syscheck-config.c", "no longer has any effect") ||
               file_contains("config/syscheck-config.c", "retired") ||
               file_contains("config/syscheck-config.c", "deprecated");
    expect(warn_hit == 1,
           "syscheck-config.c warns that prefilter_cmd is retired");

    /* Runtime: shell metacharacters in the path must not execute. */
    snprintf(path, sizeof(path), "%s/x;touch MARKER", workdir);
    snprintf(marker, sizeof(marker), "%s/MARKER", workdir);
    fp = fopen(path, "w");
    if (!fp) {
        printf("  FAIL: cannot create metachar filename (%s)\n", strerror(errno));
        failed = 1;
        goto out;
    }
    fputs("payload\n", fp);
    fclose(fp);

    unlink(marker);
    rc = OS_MD5_SHA1_File(path, md5, sha1, OS_BINARY);
    expect(rc == 0, "OS_MD5_SHA1_File hashes a metachar filename via fopen");
    expect(access(marker, F_OK) != 0,
           "hashing a ';touch MARKER' name does not execute shell text");

out:
    unlink(path);
    unlink(marker);
    rmdir(workdir);

    if (failed) {
        printf("\nFAIL: issue_3vn001l2_prefilter_retire\n");
        return 1;
    }
    printf("\nPASS: issue_3vn001l2_prefilter_retire\n");
    return 0;
}
