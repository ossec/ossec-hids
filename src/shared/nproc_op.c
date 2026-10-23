/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * Effective CPU count for thread-pool autoscaling. On Linux, honor both
 * scheduler affinity and cgroup CPU quotas (Docker --cpus / Kubernetes
 * limits) so containers do not size pools for the whole host (#2373).
 *
 * Call os_nproc_cache() before Privsep_Chroot; os_get_nproc() then returns
 * the cached value after /proc and /sys are no longer visible.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef __linux__
#include <sched.h>
#endif

#include "nproc_op.h"

/* -1 = unset; positive = cached effective CPUs after os_nproc_cache(). */
static int cached_nproc = -1;

int os_nproc_cores_from_quota(long long quota, long long period)
{
    long long cores;

    if (quota <= 0 || period <= 0) {
        return 0;
    }

    /* Ceil division so --cpus=1.5 yields 2 worker slots, not 1. */
    cores = (quota + period - 1) / period;
    if (cores < 1) {
        return 1;
    }
    if (cores > 1024) {
        return 1024;
    }
    return (int)cores;
}

int os_nproc_resolve(int affinity_cpus, int cgroup_limit)
{
    int n = affinity_cpus;

    if (n < 1) {
        n = 1;
    }
    if (cgroup_limit > 0 && cgroup_limit < n) {
        n = cgroup_limit;
    }
    return n;
}

int os_nproc_controllers_have_cpu(const char *controllers)
{
    const char *p;

    if (!controllers || !controllers[0]) {
        return 0;
    }

    for (p = controllers; *p; ) {
        const char *start;
        size_t len;

        while (*p == ',') {
            p++;
        }
        if (!*p) {
            break;
        }
        start = p;
        while (*p && *p != ',') {
            p++;
        }
        len = (size_t)(p - start);
        if ((len == 3 && strncmp(start, "cpu", 3) == 0) ||
            (len == 7 && strncmp(start, "cpuacct", 7) == 0)) {
            return 1;
        }
    }
    return 0;
}

int os_nproc_controllers_have_cpu_quota(const char *controllers)
{
    const char *p;

    if (!controllers || !controllers[0]) {
        return 0;
    }

    for (p = controllers; *p; ) {
        const char *start;
        size_t len;

        while (*p == ',') {
            p++;
        }
        if (!*p) {
            break;
        }
        start = p;
        while (*p && *p != ',') {
            p++;
        }
        len = (size_t)(p - start);
        /* Exact "cpu" only — cpuacct has no cfs_quota_us. */
        if (len == 3 && strncmp(start, "cpu", 3) == 0) {
            return 1;
        }
    }
    return 0;
}

#ifdef __linux__
/* Read cpu.max (v2) or cpu.cfs_* (v1 layout) under one directory. */
static int os_nproc_limit_at_dir(const char *dir)
{
    char path[768];
    FILE *fp;

    if (!dir || !dir[0]) {
        return 0;
    }

    if ((size_t)snprintf(path, sizeof(path), "%s/cpu.max", dir) < sizeof(path)) {
        fp = fopen(path, "r");
        if (fp) {
            char quota_str[64];
            long long period = 0;
            int matched;

            memset(quota_str, 0, sizeof(quota_str));
            matched = fscanf(fp, "%63s %lld", quota_str, &period);
            fclose(fp);

            if (matched == 2 && strcmp(quota_str, "max") != 0) {
                return os_nproc_cores_from_quota(atoll(quota_str), period);
            }
            return 0;
        }
    }

    /* v1: dir/cpu/cpu.cfs_* (fixtures / mount root) or dir/cpu.cfs_* (leaf). */
    {
        const char *q_suffixes[] = {
            "/cpu/cpu.cfs_quota_us",
            "/cpu.cfs_quota_us",
            NULL
        };
        const char *p_suffixes[] = {
            "/cpu/cpu.cfs_period_us",
            "/cpu.cfs_period_us",
            NULL
        };
        int s;

        for (s = 0; q_suffixes[s]; s++) {
            long long quota = 0;
            long long period = 0;
            char period_path[768];

            if ((size_t)snprintf(path, sizeof(path), "%s%s", dir, q_suffixes[s])
                >= sizeof(path)) {
                continue;
            }
            if ((size_t)snprintf(period_path, sizeof(period_path), "%s%s", dir,
                                 p_suffixes[s])
                >= sizeof(period_path)) {
                continue;
            }
            fp = fopen(path, "r");
            if (!fp) {
                continue;
            }
            if (fscanf(fp, "%lld", &quota) != 1) {
                fclose(fp);
                continue;
            }
            fclose(fp);
            fp = fopen(period_path, "r");
            if (!fp) {
                continue;
            }
            if (fscanf(fp, "%lld", &period) != 1) {
                fclose(fp);
                continue;
            }
            fclose(fp);
            return os_nproc_cores_from_quota(quota, period);
        }
    }

    return 0;
}

int os_nproc_cgroup_limit_range(const char *start_dir, const char *stop_root)
{
    char cur[768];
    int best = 0;
    size_t stop_len;

    if (!start_dir || !start_dir[0] || !stop_root || !stop_root[0]) {
        return 0;
    }
    if (strlen(start_dir) >= sizeof(cur)) {
        return 0;
    }
    memcpy(cur, start_dir, strlen(start_dir) + 1);
    stop_len = strlen(stop_root);

    for (;;) {
        int lim = os_nproc_limit_at_dir(cur);
        size_t cur_len;
        char *slash;

        if (lim > 0 && (best == 0 || lim < best)) {
            best = lim;
        }

        cur_len = strlen(cur);
        if (cur_len == stop_len && strcmp(cur, stop_root) == 0) {
            break;
        }
        if (cur_len <= stop_len) {
            break;
        }
        if (strncmp(cur, stop_root, stop_len) != 0 ||
            (cur[stop_len] != '\0' && cur[stop_len] != '/')) {
            break;
        }

        slash = strrchr(cur, '/');
        if (!slash || slash == cur) {
            break;
        }
        *slash = '\0';
    }

    return best;
}

static int os_nproc_join_mount(char *out, size_t out_sz, const char *mount,
                               const char *rel)
{
    int n;

    if (!rel || !rel[0] || strcmp(rel, "/") == 0) {
        n = snprintf(out, out_sz, "%s", mount);
    } else if (rel[0] == '/') {
        n = snprintf(out, out_sz, "%s%s", mount, rel);
    } else {
        n = snprintf(out, out_sz, "%s/%s", mount, rel);
    }
    return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

static void os_nproc_best_update(int *best, int lim)
{
    if (lim > 0 && (*best == 0 || lim < *best)) {
        *best = lim;
    }
}

static int os_nproc_read_proc_cgroup_limits(void)
{
    FILE *fp;
    char line[1024];
    int best = 0;
    char v2_rel[512];
    char v1_rel[512];
    int have_v2 = 0;
    int have_v1 = 0;

    v2_rel[0] = '\0';
    v1_rel[0] = '\0';

    fp = fopen("/proc/self/cgroup", "r");
    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        }

        if (!have_v2 && !strncmp(line, "0::", 3)) {
            const char *path = line + 3;
            if (!path[0]) {
                path = "/";
            }
            if (strlen(path) < sizeof(v2_rel)) {
                memcpy(v2_rel, path, strlen(path) + 1);
                have_v2 = 1;
            }
            continue;
        }

        if (!have_v1) {
            char *controllers;
            char *path;

            controllers = strchr(line, ':');
            if (!controllers) {
                continue;
            }
            controllers++;
            path = strchr(controllers, ':');
            if (!path) {
                continue;
            }
            *path = '\0';
            path++;
            if (!os_nproc_controllers_have_cpu_quota(controllers)) {
                continue;
            }
            if (!path[0]) {
                path = "/";
            }
            if (strlen(path) < sizeof(v1_rel)) {
                memcpy(v1_rel, path, strlen(path) + 1);
                have_v1 = 1;
            }
        }
    }
    fclose(fp);

    if (have_v2) {
        const char *mounts[] = {
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/unified",
            NULL
        };
        int i;

        for (i = 0; mounts[i]; i++) {
            char start[768];
            if (os_nproc_join_mount(start, sizeof(start), mounts[i], v2_rel) != 0) {
                continue;
            }
            os_nproc_best_update(&best,
                                 os_nproc_cgroup_limit_range(start, mounts[i]));
        }
    }

    if (have_v1) {
        const char *mounts[] = {
            "/sys/fs/cgroup/cpu",
            "/sys/fs/cgroup/cpu,cpuacct",
            NULL
        };
        int i;

        for (i = 0; mounts[i]; i++) {
            char start[768];
            if (os_nproc_join_mount(start, sizeof(start), mounts[i], v1_rel) != 0) {
                continue;
            }
            /* Walk parents under the controller mount (pod / slice quotas). */
            os_nproc_best_update(&best,
                                 os_nproc_cgroup_limit_range(start, mounts[i]));
        }
    }

    return best;
}

int os_nproc_read_cgroup_cpu_limit(const char *cgroup_root)
{
    int best;

    /* Explicit root (unit tests): single-directory read, no /proc walk. */
    if (cgroup_root && cgroup_root[0]) {
        return os_nproc_limit_at_dir(cgroup_root);
    }

    best = os_nproc_read_proc_cgroup_limits();
    if (best > 0) {
        return best;
    }

    /* Fallback: mount-root files (simple container layouts). */
    return os_nproc_limit_at_dir("/sys/fs/cgroup");
}

static int os_nproc_affinity(void)
{
#ifdef CPU_COUNT
    cpu_set_t set;

    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) != 0) {
        return 0;
    }
    return CPU_COUNT(&set);
#else
    return 0;
#endif
}
#endif /* __linux__ */

#if !defined(__linux__)
int os_nproc_read_cgroup_cpu_limit(const char *cgroup_root)
{
    (void)cgroup_root;
    return 0;
}

int os_nproc_cgroup_limit_range(const char *start_dir, const char *stop_root)
{
    (void)start_dir;
    (void)stop_root;
    return 0;
}
#endif

static int os_nproc_probe(void)
{
    int affinity = 1;

#ifdef WIN32
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwNumberOfProcessors >= 1) {
            affinity = (int)si.dwNumberOfProcessors;
        }
    }
    return os_nproc_resolve(affinity, 0);
#elif defined(__linux__)
    affinity = os_nproc_affinity();
    if (affinity < 1) {
        long online = sysconf(_SC_NPROCESSORS_ONLN);
        affinity = (online < 1) ? 1 : (int)online;
    }
    return os_nproc_resolve(affinity, os_nproc_read_cgroup_cpu_limit(NULL));
#else
    {
        long online = sysconf(_SC_NPROCESSORS_ONLN);
        if (online >= 1) {
            affinity = (int)online;
        }
    }
    return os_nproc_resolve(affinity, 0);
#endif
}

void os_nproc_cache(void)
{
    if (cached_nproc > 0) {
        return;
    }
    cached_nproc = os_nproc_probe();
    if (cached_nproc < 1) {
        cached_nproc = 1;
    }
}

int os_get_nproc(void)
{
    if (cached_nproc > 0) {
        return cached_nproc;
    }
    return os_nproc_probe();
}
