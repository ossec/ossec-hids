# Linux end-to-end tests (install / upgrade / feature smoke / JSON syslog)

This module is **separate** from the compile matrix in [`../build-test/`](../build-test/).
It validates real installs on:

- **Dedicated hosts** over SSH (community primary: Rocky Linux 10 at `root@10.66.6.82`)
- **Podman** systemd containers (local / CI-friendly)

Windows E2E is out of scope here.

## Quick start

From the **repo root**:

```bash
# Compile gate then E2E (optional wrapper)
./testsuite/run-all.sh --inventory testsuite/e2e-linux/inventory.community.yaml --backend ssh

# E2E only
./testsuite/e2e-linux/run.sh --inventory testsuite/e2e-linux/inventory.community.yaml

# Single suite / backend
./testsuite/e2e-linux/run.sh --inventory ... --backend podman --suite 01-install-server

# JSON syslog / alerts.json (#1907) — prints alerts.json + captured datagram
./testsuite/e2e-linux/run.sh --inventory testsuite/e2e-linux/inventory.community.yaml \
    --backend ssh --suite 05-alerts-json-syslog --no-build-packages
```

Copy [`inventory.example.yaml`](inventory.example.yaml) to `inventory.community.yaml` (gitignored) for local overrides.

Helper inventories checked in for convenience:

- `inventory.ssh-server.yaml` — community Rocky 10 server only
- `inventory.agent-test.yaml` — community server + Rocky 10 Podman agent

Primary validated path: **SSH Rocky 10 server** (`root@10.66.6.82`) with **Rocky 10 Podman agent** using el10 RPMs from `mock -r rocky-10-x86_64`.

## Prerequisites

| Need | Notes |
|------|--------|
| Controller | `bash`, `python3` + PyYAML, `ssh`/`scp`, `podman` (for Podman backend), `mock`/`rpmbuild` (to auto-build Rocky 10 RPMs) |
| SSH hosts | Key-based login; suites may install/remove OSSEC packages and restart services |
| Packages | Prefer RPMs/Debs in `testsuite/` (`E2E_PACKAGE_DIR`). Auto-built via mock (`rocky-10-x86_64`) and `build-deb.sh` unless `--no-build-packages` |

## Suites

| Suite | Purpose |
|-------|---------|
| `01-install-server` | Install server package/source, start, assert daemons |
| `02-install-agent` | Install agent, enroll keys, assert connection evidence |
| `03-feature-smoke` | `ossec-logtest` fixture + syscheck soft smoke |
| `04-upgrade-server` | Baseline (`E2E_BASE_PACKAGE` or current) → current; preserve config marker |
| `05-alerts-json-syslog` | Enable `jsonout_output` + JSON `syslog_output`, inject an sshd failure, print `alerts.json` and the UDP datagram (`agent_name`) |
| `syscheck/*` | Extended FIM (queue gate, 550/553/554, realtime vs scheduled, filters, report_changes) |

Default `run.sh` runs **01–05**. The JSON syslog suite needs a **this-branch** server install (`01-install-server` with packages built from this tree, or an already-upgraded host). It listens on UDP `127.0.0.1:10514` (`E2E_JSON_SYSLOG_PORT`) and prints the matching `alerts.json` line, the syslog datagram, and a pretty-printed payload.

Extended syscheck:

```bash
./testsuite/e2e-linux/run.sh --inventory testsuite/e2e-linux/inventory.ssh-server.yaml --suite syscheck --no-build-packages
./testsuite/e2e-linux/run.sh --inventory ... --extended   # 01–04 then syscheck/*
./testsuite/e2e-linux/run.sh --inventory ... --suite 10-queue-gate
```

Syscheck suites hard-fail on analysisd queue `socketerr` (unlike the soft path in `03-feature-smoke`).

## Environment

- `E2E_INVENTORY` — inventory path
- `E2E_BACKEND` — `ssh` or `podman`
- `E2E_PACKAGE_DIR` — where to find/build packages (default: `testsuite/`)
- `E2E_BASE_PACKAGE` — prior RPM/Deb file or directory for upgrade tests
- `E2E_TIMEOUT` — assertion wait seconds (default 120)
- `E2E_KEEP=1` — keep Podman containers / remote scratch
- `E2E_BUILD_PACKAGES=0` — skip auto package builds (source-install fallback)

## Layout

```
e2e-linux/
  run.sh
  inventory.example.yaml
  inventory.community.yaml   # gitignored
  lib/                       # transport, pkg, assert, enroll, artifacts, syscheck
  suites/
    01–05*.sh
    syscheck/                # extended FIM (10–15)
  fixtures/
    syscheck/
  images/rocky10|ubuntu2404
```

Suites call only `transport_*` helpers — they do not hard-code SSH vs Podman.
