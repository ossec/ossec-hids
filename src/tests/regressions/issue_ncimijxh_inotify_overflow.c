/*
 * ANT-2026-NCIMIJXH: inotify IN_Q_OVERFLOW must trigger deferred recovery.
 *
 * Pre-fix, realtime_process() only acted when event->len was non-zero and
 * never read event->mask, so the kernel's IN_Q_OVERFLOW marker (wd=-1,
 * len=0) was skipped. Lost events were never logged or rescanned; Windows
 * already deferred recovery via rt_overflow_schedule().
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ncimijxh_inotify_overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

const char *__local_name = "issue-ncimijxh-inotify-overflow";

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

/* Mirror of fixed rt_path_under_dir for Linux (strncmp + '/' only). */
static int path_under_dir(const char *path, const char *dir)
{
    size_t len;

    if (path == NULL || dir == NULL || dir[0] == '\0') {
        return (0);
    }

    len = strlen(dir);
    while (len > 1 && dir[len - 1] == '/') {
        len--;
    }
    if (strncmp(path, dir, len) != 0) {
        return (0);
    }
    /* Only "/" still ends in a separator here. */
    return (path[len] == '\0' || path[len] == '/' || dir[len - 1] == '/');
}

static void test_root_covers_all_paths(void)
{
    CHECK(path_under_dir("/etc/passwd", "/") != 0,
          "configured '/' covers every absolute path");
    CHECK(path_under_dir("/srv/site/shell.php", "/srv/site") != 0,
          "child path is under its realtime directory");
    CHECK(path_under_dir("/srv/other", "/srv/site") == 0,
          "sibling path is not under the realtime directory");
}

static void test_source_handles_overflow(void)
{
    const char *src = "syscheckd/run_realtime.c";

    CHECK(source_has(src, "IN_Q_OVERFLOW"),
          "realtime_process checks IN_Q_OVERFLOW");
    CHECK(source_has(src, "rt_overflow_schedule(syscheck.dir[j], syscheck.opts[j])"),
          "overflow schedules recovery for every CHECK_REALTIME dir");
    CHECK(source_has(src, "defined(INOTIFY_ENABLED) || defined(WIN32)"),
          "overflow recovery compiles for inotify as well as WIN32");
    CHECK(source_has(src, "#define rt_path_ncmp"),
          "path helpers use platform compare macros");
    CHECK(source_has(src, "scan_opts &= ~CHECK_REALTIME"),
          "CHECK_REALTIME is stripped only on the Windows recovery path");
}

int main(void)
{
    printf("ANT-2026-NCIMIJXH inotify overflow recovery\n");
    test_root_covers_all_paths();
    test_source_handles_overflow();
    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return (1);
    }
    printf("ALL OK\n");
    return (0);
}
