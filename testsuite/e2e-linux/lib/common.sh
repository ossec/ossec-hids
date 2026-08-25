#!/usr/bin/env bash
# Shared helpers for e2e-linux (controller-side).
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTSUITE_DIR="$(cd "$E2E_DIR/.." && pwd)"
ROOT_DIR="$(cd "$TESTSUITE_DIR/.." && pwd)"

E2E_PACKAGE_DIR="${E2E_PACKAGE_DIR:-$TESTSUITE_DIR}"
E2E_TIMEOUT="${E2E_TIMEOUT:-120}"
E2E_KEEP="${E2E_KEEP:-0}"
E2E_REMOTE_TMP="${E2E_REMOTE_TMP:-/var/tmp/ossec-e2e}"
E2E_PODMAN_NETWORK="${E2E_PODMAN_NETWORK:-ossec-e2e}"
OSSEC_DIR="${OSSEC_DIR:-/var/ossec}"

log()  { printf '[e2e] %s\n' "$*"; }
warn() { printf '[e2e] WARN: %s\n' "$*" >&2; }
die()  { printf '[e2e] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

wait_for() {
    local desc="$1" timeout="${2:-$E2E_TIMEOUT}"
    shift 2
    local start now
    start=$(date +%s)
    while true; do
        if "$@"; then
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= timeout )); then
            die "timeout after ${timeout}s waiting for: $desc"
        fi
        sleep 2
    done
}
