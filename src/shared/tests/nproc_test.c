/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * Unit / fixture tests for os_get_nproc cgroup-aware CPU sizing (#2373).
 *
 * Usage:
 *   ./nproc_test              # fixture tests (default)
 *   ./nproc_test live         # print os_get_nproc() and exit 0
 *   ./nproc_test expect N     # fail unless os_get_nproc() == N (e2e/podman)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nproc_op.h"

static int failures = 0;

static void expect_int(const char *name, int got, int want)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s: got %d want %d\n", name, got, want);
        failures++;
    }
}

static int write_file(const char *path, const char *contents)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "FAIL: fopen %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fputs(contents, fp) < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int test_quota_math(void)
{
    expect_int("unlimited quota -1", os_nproc_cores_from_quota(-1, 100000), 0);
    expect_int("zero period", os_nproc_cores_from_quota(100000, 0), 0);
    expect_int("1.0 cpu", os_nproc_cores_from_quota(100000, 100000), 1);
    expect_int("2.0 cpu", os_nproc_cores_from_quota(200000, 100000), 2);
    expect_int("1.5 cpu ceil", os_nproc_cores_from_quota(150000, 100000), 2);
    expect_int("0.5 cpu ceil", os_nproc_cores_from_quota(50000, 100000), 1);
    return failures ? 1 : 0;
}

static int test_resolve(void)
{
    /* Host affinity 32, cgroup --cpus=2 => 2 (the #2373 failure mode). */
    expect_int("cgroup caps affinity", os_nproc_resolve(32, 2), 2);
    expect_int("no cgroup limit", os_nproc_resolve(8, 0), 8);
    expect_int("affinity smaller", os_nproc_resolve(2, 8), 2);
    expect_int("bad affinity", os_nproc_resolve(0, 0), 1);
    expect_int("bad affinity with limit", os_nproc_resolve(-1, 4), 1);
    return failures ? 1 : 0;
}

static int test_controller_tokens(void)
{
    expect_int("cpu alone", os_nproc_controllers_have_cpu("cpu"), 1);
    expect_int("cpu,cpuacct", os_nproc_controllers_have_cpu("cpu,cpuacct"), 1);
    expect_int("cpuacct alone", os_nproc_controllers_have_cpu("cpuacct"), 1);
    expect_int("cpuset is not cpu", os_nproc_controllers_have_cpu("cpuset"), 0);
    expect_int("memory,cpuset", os_nproc_controllers_have_cpu("memory,cpuset"), 0);
    expect_int("empty controllers", os_nproc_controllers_have_cpu(""), 0);
    expect_int("quota needs cpu token", os_nproc_controllers_have_cpu_quota("cpuacct"), 0);
    expect_int("quota accepts cpu", os_nproc_controllers_have_cpu_quota("cpu,cpuacct"), 1);
    return failures ? 1 : 0;
}

static int test_nproc_cache(void)
{
    int before;
    int after;

    before = os_get_nproc();
    os_nproc_cache();
    after = os_get_nproc();
    if (before < 1 || after < 1 || before != after) {
        fprintf(stderr, "FAIL: cache: before=%d after=%d\n", before, after);
        failures++;
        return 1;
    }
    /* Second cache must keep the same snapshot. */
    os_nproc_cache();
    expect_int("cache stable", os_get_nproc(), after);
    return failures ? 1 : 0;
}

static int join_path(char *out, size_t out_sz, const char *dir, const char *leaf)
{
    int n = snprintf(out, out_sz, "%s/%s", dir, leaf);
    if (n < 0 || (size_t)n >= out_sz) {
        fprintf(stderr, "FAIL: path too long under %s\n", dir);
        failures++;
        return -1;
    }
    return 0;
}

static int test_cgroup_v2_fixture(void)
{
    char dir[] = "/tmp/ossec-nproc-v2-XXXXXX";
    char path[sizeof(dir) + 16];

    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        failures++;
        return 1;
    }

    if (join_path(path, sizeof(path), dir, "cpu.max") != 0) {
        return 1;
    }
    if (write_file(path, "200000 100000\n") != 0) {
        failures++;
        return 1;
    }
    expect_int("v2 cpu.max 2.0", os_nproc_read_cgroup_cpu_limit(dir), 2);

    if (write_file(path, "max 100000\n") != 0) {
        failures++;
        return 1;
    }
    expect_int("v2 cpu.max unlimited", os_nproc_read_cgroup_cpu_limit(dir), 0);

    unlink(path);
    rmdir(dir);
    return failures ? 1 : 0;
}

static int test_cgroup_v1_fixture(void)
{
    char dir[] = "/tmp/ossec-nproc-v1-XXXXXX";
    char cpu_dir[sizeof(dir) + 8];
    char path[sizeof(dir) + 32];

    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        failures++;
        return 1;
    }

    if (join_path(cpu_dir, sizeof(cpu_dir), dir, "cpu") != 0) {
        return 1;
    }
    if (mkdir(cpu_dir, 0700) != 0) {
        fprintf(stderr, "FAIL: mkdir %s: %s\n", cpu_dir, strerror(errno));
        failures++;
        return 1;
    }

    if (join_path(path, sizeof(path), cpu_dir, "cpu.cfs_quota_us") != 0) {
        return 1;
    }
    if (write_file(path, "100000\n") != 0) {
        failures++;
        return 1;
    }
    if (join_path(path, sizeof(path), cpu_dir, "cpu.cfs_period_us") != 0) {
        return 1;
    }
    if (write_file(path, "100000\n") != 0) {
        failures++;
        return 1;
    }
    expect_int("v1 cfs 1.0", os_nproc_read_cgroup_cpu_limit(dir), 1);

    if (join_path(path, sizeof(path), cpu_dir, "cpu.cfs_quota_us") != 0) {
        return 1;
    }
    if (write_file(path, "-1\n") != 0) {
        failures++;
        return 1;
    }
    expect_int("v1 cfs unlimited", os_nproc_read_cgroup_cpu_limit(dir), 0);

    if (join_path(path, sizeof(path), cpu_dir, "cpu.cfs_quota_us") == 0) {
        unlink(path);
    }
    if (join_path(path, sizeof(path), cpu_dir, "cpu.cfs_period_us") == 0) {
        unlink(path);
    }
    rmdir(cpu_dir);
    rmdir(dir);
    return failures ? 1 : 0;
}

static int test_missing_root(void)
{
    expect_int("missing root", os_nproc_read_cgroup_cpu_limit("/tmp/ossec-nproc-missing-xyz"), 0);
    return failures ? 1 : 0;
}

static int test_cgroup_v2_ancestor_walk(void)
{
    char dir[] = "/tmp/ossec-nproc-walk-XXXXXX";
    char child[sizeof(dir) + 16];
    char path[sizeof(dir) + 32];

    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        failures++;
        return 1;
    }
    if (join_path(path, sizeof(path), dir, "cpu.max") != 0) {
        return 1;
    }
    /* Parent unlimited; child capped at 2 — walk must keep the tighter limit. */
    if (write_file(path, "max 100000\n") != 0) {
        failures++;
        return 1;
    }
    if (join_path(child, sizeof(child), dir, "child") != 0) {
        return 1;
    }
    if (mkdir(child, 0700) != 0) {
        fprintf(stderr, "FAIL: mkdir %s: %s\n", child, strerror(errno));
        failures++;
        return 1;
    }
    if (join_path(path, sizeof(path), child, "cpu.max") != 0) {
        return 1;
    }
    if (write_file(path, "200000 100000\n") != 0) {
        failures++;
        return 1;
    }
    expect_int("v2 ancestor walk child=2", os_nproc_cgroup_limit_range(child, dir), 2);

    /* Parent tighter than child. */
    if (join_path(path, sizeof(path), dir, "cpu.max") != 0) {
        return 1;
    }
    if (write_file(path, "100000 100000\n") != 0) {
        failures++;
        return 1;
    }
    if (join_path(path, sizeof(path), child, "cpu.max") != 0) {
        return 1;
    }
    if (write_file(path, "400000 100000\n") != 0) {
        failures++;
        return 1;
    }
    expect_int("v2 ancestor walk parent=1", os_nproc_cgroup_limit_range(child, dir), 1);

    if (join_path(path, sizeof(path), child, "cpu.max") == 0) {
        unlink(path);
    }
    rmdir(child);
    if (join_path(path, sizeof(path), dir, "cpu.max") == 0) {
        unlink(path);
    }
    rmdir(dir);
    return failures ? 1 : 0;
}

static int run_fixtures(void)
{
    test_quota_math();
    test_resolve();
    test_controller_tokens();
    test_nproc_cache();
#ifdef __linux__
    test_cgroup_v2_fixture();
    test_cgroup_v1_fixture();
    test_cgroup_v2_ancestor_walk();
    test_missing_root();
#endif

    if (failures) {
        fprintf(stderr, "nproc_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("nproc_test: OK\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "live") == 0) {
        printf("%d\n", os_get_nproc());
        return 0;
    }

    if (argc >= 3 && strcmp(argv[1], "expect") == 0) {
        int want = atoi(argv[2]);
        int got = os_get_nproc();

        if (got != want) {
            fprintf(stderr, "FAIL: os_get_nproc()=%d want %d\n", got, want);
            return 1;
        }
        printf("nproc_test expect %d: OK (got %d)\n", want, got);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "help") == 0) {
        fprintf(stderr, "Usage: %s [live|expect N]\n", argv[0]);
        return 0;
    }

    return run_fixtures();
}
