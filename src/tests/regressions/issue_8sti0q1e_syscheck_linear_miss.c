/*
 * ANT-2026-8STI0Q1E: DB_Search must not linear-scan the integrity DB on an
 * index miss when the per-agent hash index is complete.
 *
 * Build (from src/ after make shared.a):
 *   make -f tests/regressions/Makefile issue_8sti0q1e_syscheck_linear_miss
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "eventinfo.h"
#include "config.h"

/* Provided by shared/file_op.o when linking shared.a; keep a weak fallback. */
const char *__local_name __attribute__((weak)) = "issue-8sti0q1e-syscheck-linear-miss";

/* Stubs for analysisd pieces pulled by the syscheck decoder. */
_Config Config;
int getDecoderfromlist(const char *name)
{
    (void)name;
    return 1;
}

extern unsigned int __db_search_linear_calls;
void SyscheckInit(void);
int Syscheck_TestDBSearch(Eventinfo *lf, const char *f_name, const char *c_sum);

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static int mkdir_p(const char *path)
{
    char tmp[512];
    size_t len;
    size_t i;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    for (i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int write_db(const char *path, int n)
{
    FILE *fp;
    int i;

    fp = fopen(path, "w");
    if (!fp) {
        perror(path);
        return 0;
    }
    for (i = 0; i < n; i++) {
        /* Minimal checksum-ish token + filename (space-separated). */
        fprintf(fp, "0:0:0:0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb !%d /seed-%04d\n",
                i, i);
    }
    fclose(fp);
    return 1;
}

static void run_search(const char *location, const char *fname, const char *csum)
{
    Eventinfo lf;

    memset(&lf, 0, sizeof(lf));
    lf.location = (char *)location;
    lf.time = 1;
    lf.filename = NULL;
    lf.data = NULL;
    lf.full_log = NULL;
    lf.log = NULL;
    lf.decoder_info = NULL;

    (void)Syscheck_TestDBSearch(&lf, fname, csum);
    free(lf.filename);
    free(lf.full_log);
}

int main(void)
{
    char cwd[512];
    char dbdir[600];
    char dbpath[700];
    const char *location = "(agent1) 10.0.0.5->syscheck";
    const char *csum =
        "0:0:0:0:cccccccccccccccccccccccccccccccc:dddddddddddddddddddddddddddddddd";
    unsigned int calls_after_seed;
    unsigned int calls_after_miss;

    printf("ANT-2026-8STI0Q1E syscheck index-miss linear scan\n");

    if (!getcwd(cwd, sizeof(cwd))) {
        perror("getcwd");
        return 1;
    }

    snprintf(dbdir, sizeof(dbdir), "%s/queue/syscheck", cwd);
    if (mkdir_p(dbdir) != 0) {
        perror(dbdir);
        return 1;
    }
    snprintf(dbpath, sizeof(dbpath), "%s/%s", dbdir, location);
    if (!write_db(dbpath, 200)) {
        return 1;
    }

    memset(&Config, 0, sizeof(Config));
    Config.syscheck_alert_new = 0;
    Config.syscheck_report_new_as_changed = 0;
    Config.syscheck_ignore = NULL;

    SyscheckInit();

    /* BuildIndex loads the seeded DB; a miss must go straight to append. */
    __db_search_linear_calls = 0;
    run_search(location, "/brand-new-0001", csum);
    calls_after_seed = __db_search_linear_calls;
    printf("  info: linear calls on first miss = %u\n", calls_after_seed);
    CHECK(calls_after_seed == 0,
          "complete index: first miss must not call DB_SearchLinear");

    /* Another new name: still no whole-file scan. */
    __db_search_linear_calls = 0;
    run_search(location, "/brand-new-0002", csum);
    calls_after_miss = __db_search_linear_calls;
    printf("  info: linear calls on later miss = %u\n", calls_after_miss);
    CHECK(calls_after_miss == 0,
          "complete index: later miss must not call DB_SearchLinear");

    unlink(dbpath);

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
