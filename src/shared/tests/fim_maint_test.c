/* Unit tests for FIM maintenance marker helpers (#2283 follow-up). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "shared.h"

static int failures = 0;

static void expect_int(const char *name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    }
}

static void expect_str(const char *name, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("FAIL %s: got '%s' want '%s'\n", name, got, want);
        failures++;
    }
}

static void expect_true(const char *name, int cond)
{
    if (!cond) {
        printf("FAIL %s\n", name);
        failures++;
    }
}

int main(void)
{
    char path[OS_FLSIZE + 1];
    char loc_path[OS_FLSIZE + 1];
    char tmp[] = "/tmp/ossec-fim-maint-test.XXXXXX";
    int fd;
    syscheck_maint_info info;
    syscheck_maint_info empty;

    /* Path builders */
    syscheck_maint_path(NULL, NULL, path, sizeof(path));
    expect_str("local path", path, SYSCHECK_DIR "/.syscheck.maint");

    syscheck_maint_path("web1", "10.0.0.5", path, sizeof(path));
    expect_str("agent path", path, SYSCHECK_DIR "/.(web1) 10.0.0.5.maint");

    syscheck_maint_path_from_location("syscheck", loc_path, sizeof(loc_path));
    expect_str("loc syscheck", loc_path, SYSCHECK_DIR "/.syscheck.maint");

    syscheck_maint_path_from_location("(web1) 10.0.0.5->syscheck",
                                      loc_path, sizeof(loc_path));
    expect_str("loc agent", loc_path,
               SYSCHECK_DIR "/.(web1) 10.0.0.5.maint");

    /* Round-trip marker I/O on a tempfile (DecodeSyscheck uses these helpers). */
    fd = mkstemp(tmp);
    expect_true("mkstemp", fd >= 0);
    if (fd >= 0) {
        close(fd);
        unlink(tmp);
    }

    memset(&empty, 0, sizeof(empty));
    expect_int("missing marker", syscheck_maint_read_path(tmp, &empty), 0);

    memset(&info, 0, sizeof(info));
    info.enabled = 1;
    info.enabled_at = 1700000000;
    info.pending_end = 0;
    info.silent_updates = 3;
    expect_int("write marker", syscheck_maint_write_path(tmp, &info), 1);

    memset(&empty, 0, sizeof(empty));
    expect_int("read marker", syscheck_maint_read_path(tmp, &empty), 1);
    expect_int("enabled", empty.enabled, 1);
    expect_true("enabled_at", empty.enabled_at == (time_t)1700000000);
    expect_int("pending_end off", empty.pending_end, 0);
    expect_true("silent_updates", empty.silent_updates == 3UL);

    /* pending_end flip mirrors DecodeSyscheck HC_SK_DB_COMPLETED clear path */
    empty.pending_end = 1;
    expect_int("write pending_end", syscheck_maint_write_path(tmp, &empty), 1);
    memset(&info, 0, sizeof(info));
    expect_int("read pending_end", syscheck_maint_read_path(tmp, &info), 1);
    expect_int("pending_end on", info.pending_end, 1);

    expect_str("list tag pending", syscheck_maint_list_tag(&info),
               "Maint(pending-end)");
    info.pending_end = 0;
    expect_str("list tag on", syscheck_maint_list_tag(&info), "Maint");
    info.enabled = 0;
    expect_str("list tag off", syscheck_maint_list_tag(&info), "");

    /* Clear marker (same as clear_location / end-after-baseline) */
    expect_true("unlink marker", unlink(tmp) == 0 || errno == ENOENT);
    expect_int("gone after clear", syscheck_maint_read_path(tmp, &info), 0);

    /* set_pending_end must fail without an existing marker */
    expect_int("pending_end without marker",
               syscheck_maint_set_pending_end("no-such-agent", "127.0.0.1", 1),
               0);

    if (failures) {
        printf("FAILED: %d assertion(s)\n", failures);
        return (1);
    }

    printf("PASS: fim_maint_test\n");
    return (0);
}
