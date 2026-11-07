/*
 * ANT-2026-ODWFEHAC: realtime dirtb must drop watches on IN_IGNORED.
 *
 * Pre-fix, realtime_adddir() stored a strdup'd path for every inotify
 * watch descriptor, but realtime_process() never removed entries. Named
 * events only ran when event->len was non-zero, so IN_IGNORED /
 * IN_DELETE_SELF left stale paths forever. A local user who can mkdir/rmdir
 * under realtime="yes" grew root syscheckd without bound.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_odwfehac_dirtb_leak
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

const char *__local_name = "issue-odwfehac-dirtb-leak";

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

/* Contract of the IN_IGNORED path: delete frees the stored path string. */
static void test_hash_delete_frees_path(void)
{
    OSHash *dirtb;
    char *path;
    char *gone;

    dirtb = OSHash_Create();
    CHECK(dirtb != NULL, "created dirtb stand-in");
    if (!dirtb) {
        return;
    }

    path = strdup("/srv/site/tmp/deep/dir");
    CHECK(path != NULL, "allocated watch path");
    CHECK(OSHash_Add(dirtb, "42", path) == 2, "stored watch under wd 42");
    CHECK(OSHash_Get(dirtb, "42") == path, "lookup returns stored path");

    gone = (char *)OSHash_Delete(dirtb, "42");
    CHECK(gone == path, "IN_IGNORED delete returns the path");
    free(gone);
    CHECK(OSHash_Get(dirtb, "42") == NULL, "watch entry is gone after delete");

    OSHash_Free(dirtb);
}

static void test_source_cleans_dirtb(void)
{
    const char *src = "syscheckd/run_realtime.c";

    CHECK(source_has(src, "IN_IGNORED"),
          "realtime_process handles IN_IGNORED");
    CHECK(source_has(src, "OSHash_Delete(syscheck.realtime->dirtb, wdchar)"),
          "IN_IGNORED removes the dirtb entry");
    CHECK(source_has(src, "realtime_purge_dirtb"),
          "overflow reconciles dirtb via realtime_purge_dirtb");
    CHECK(source_has(src, "event->len && dir"),
          "named events skip a missing dirtb entry");
}

int main(void)
{
    printf("ANT-2026-ODWFEHAC realtime dirtb leak\n");
    test_hash_delete_frees_path();
    test_source_cleans_dirtb();
    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return (1);
    }
    printf("ALL OK\n");
    return (0);
}
