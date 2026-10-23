/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __NPROC_OP_H
#define __NPROC_OP_H

/* Effective CPU count for autoscaling worker pools.
 * Linux: min(sched affinity, cgroup CPU quota) when a quota is set;
 * otherwise affinity (or 1 on error). Non-Linux: online processor count.
 *
 * Call os_nproc_cache() once before chroot so later os_get_nproc() still
 * returns the pre-jail value (analysisd opens /proc and /sys only then). */
int os_get_nproc(void);

/* Snapshot os_get_nproc() for use after Privsep_Chroot. Idempotent. */
void os_nproc_cache(void);

/* Ceil(quota/period) cores; 0 when unlimited/invalid (quota <= 0 or period <= 0). */
int os_nproc_cores_from_quota(long long quota, long long period);

/* Read cgroup v2 cpu.max or v1 cfs quota under cgroup_root.
 * cgroup_root NULL => resolve from /proc/self/cgroup. Returns 0 when no limit. */
int os_nproc_read_cgroup_cpu_limit(const char *cgroup_root);

/* Compose affinity and optional cgroup limit (0 = no limit). Always >= 1. */
int os_nproc_resolve(int affinity_cpus, int cgroup_limit);

/* Most restrictive positive CPU limit from start_dir up through stop_root. */
int os_nproc_cgroup_limit_range(const char *start_dir, const char *stop_root);

/* True if controller list has exact token "cpu" or "cpuacct" (not cpuset). */
int os_nproc_controllers_have_cpu(const char *controllers);

/* True if controller list has exact token "cpu" (needed for cfs quota files). */
int os_nproc_controllers_have_cpu_quota(const char *controllers);

#endif /* __NPROC_OP_H */
