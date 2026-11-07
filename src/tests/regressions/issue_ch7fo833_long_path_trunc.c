/*
 * ANT-2026-CH7FO833: Unix FIM alerts must keep the full file path.
 *
 * Pre-fix, read_file() and realtime_checksumfile() snprintf'd into
 * alert_msg with a stale 916/912 limit even though the buffer is
 * OS_MAXSTR+1. Paths longer than ~757 characters were cut, so every file
 * under a deep tree reached the manager under one truncated name and
 * auto_ignore silenced later changes.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ch7fo833_long_path_trunc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

const char *__local_name = "issue-ch7fo833-long-path-trunc";

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

/* Build an 810-character path (under PATH_MAX, over the old ~757 limit). */
static void make_long_path(char *out, size_t outsz)
{
    size_t i;
    const char *prefix = "/srv/www/";
    size_t n;

    snprintf(out, outsz, "%s", prefix);
    n = strlen(out);
    for (i = n; i + 1 < outsz && i < 810; i++) {
        out[i] = 'a' + (int)((i - n) % 26);
    }
    if (i + 12 < outsz) {
        memcpy(out + i, "/index.php", 11);
    } else {
        out[i] = '\0';
    }
}

static const char *msg_path(const char *msg)
{
    const char *sp = strchr(msg, ' ');
    return (sp ? sp + 1 : NULL);
}

static void test_limits_preserve_long_paths(void)
{
    char path[1024];
    char truncated[OS_MAXSTR + 1];
    char full[OS_MAXSTR + 1];
    const char *sum = "20:33188:1000:1000:0123456789abcdef0123456789abcdef:"
                      "0123456789abcdef0123456789abcdef01234567:"
                      "0123456789abcdef0123456789abcdef0123456789abcdef"
                      "0123456789abcdef";
    const char *tpath;
    const char *fpath;

    make_long_path(path, sizeof(path));
    CHECK(strlen(path) > 757, "sample path is longer than the old 757-char cut");

    snprintf(truncated, 916, "%s %s", sum, path);
    tpath = msg_path(truncated);
    CHECK(tpath != NULL, "916-byte format produced a path field");
    CHECK(tpath && strcmp(tpath, path) != 0,
          "old 916 limit truncates the path (bug demonstration)");

    snprintf(full, OS_MAXSTR, "%s %s", sum, path);
    fpath = msg_path(full);
    CHECK(fpath != NULL && strcmp(fpath, path) == 0,
          "OS_MAXSTR keeps the full path after the checksum");
}

static void test_source_uses_buffer_size(void)
{
    CHECK(!source_has("syscheckd/create_db.c", "snprintf(alert_msg, 916,"),
          "create_db.c no longer formats with 916");
    CHECK(!source_has("syscheckd/create_db.c", "alert_msg[916] = '\\0'"),
          "create_db.c dropped the 916 terminator");
    CHECK(!source_has("syscheckd/run_realtime.c", "snprintf(alert_msg, 912,"),
          "run_realtime.c no longer formats with 912");
    CHECK(source_has("syscheckd/create_db.c",
                     "snprintf(alert_msg, OS_MAXSTR, \"%ld:%d:%d:%d:%s:%s:%s %s\""),
          "baseline Unix snprintf uses OS_MAXSTR");
}

int main(void)
{
    printf("ANT-2026-CH7FO833 long path FIM truncation\n");
    test_limits_preserve_long_paths();
    test_source_uses_buffer_size();
    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return (1);
    }
    printf("ALL OK\n");
    return (0);
}
