# PR #2207 VM Test Results

**Branch:** `test/pr-2207-signal-support`  
**VM:** `root@192.168.122.193` (Rocky Linux 9.7)  
**Install path:** `/var/ossec`  
**Last validated:** 2026-05-27 (post remediation v3 + v4)

## Build

```bash
cd /root/ossec-hids-build/src
make clean && make TARGET=server
```

Full clean rebuild required on VM to avoid `__isoc23_*` / `__isoc99_*` linker mismatches from stale `libcJSON.a` or object files.

Deploy:

```bash
cp ossec-analysisd ossec-agentd ossec-remoted ossec-logcollector \
   ossec-syscheckd ossec-monitord ossec-execd /var/ossec/bin/
/var/ossec/bin/ossec-control restart
```

## Automated regression (`contrib/test-reload.sh`)

| Run | Result |
|-----|--------|
| Default smoke + bad-rules + `ar.conf` | **PASS** (exit 0) |
| `TEST_RELOAD_STRESS=1` (50 reloads) | **PASS** — analysisd PID stable |

Checks include: PID stability, SIGHUP logging, no placeholder reload messages, `ar.conf` line count unchanged after reload, analysisd survives malformed rules reload with staging-abort logging (no partial-reload false positive).

## Remediation validated on VM

| Item | Status |
|------|--------|
| Staging abort preserves live rules | **PASS** (bad-rules test) |
| AR `ar.conf` serialize (not truncated to 2 lines) | **PASS** (4 lines unchanged) |
| Distinct staging vs post-commit reload messages | **PASS** (logs) |
| `max_config_reloads` in `internal_options.conf` | **Present** on VM |
| 50x reload stress | **PASS** |

## Prior PR #2207 matrix (historical)

Earlier runs on this VM (before full analysisd reload) documented placeholder behavior for analysisd/monitord/execd. **Current branch:** analysisd performs full atomic staging reload; placeholder messages must not appear (`test-reload.sh` verifies).

## Merge readiness

- All planned remediation todos (review v2–v4) implemented in tree.
- VM gate: `contrib/test-reload.sh` exit 0 with rebuilt binaries.
- Recommended before merge: commit branch, push, update PR #2207 description with reload semantics and `BUILDING.md` link.
- Optional: `TEST_RELOAD_LEAK=1`, agent-side reload test on a host with `ossec-agentd` + `<allow-reload-reconnect>yes`.
