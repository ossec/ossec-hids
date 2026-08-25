#!/usr/bin/env bash
# Linux E2E entrypoint: install / agent / feature smoke / upgrade / JSON syslog / syscheck.
# Usage (from repo root):
#   ./testsuite/e2e-linux/run.sh --inventory testsuite/e2e-linux/inventory.community.yaml
#   ./testsuite/e2e-linux/run.sh --inventory ... --backend ssh --suite 01-install-server
#   ./testsuite/e2e-linux/run.sh --inventory ... --suite 05-alerts-json-syslog --no-build-packages
#   ./testsuite/e2e-linux/run.sh --inventory ... --suite syscheck
#   ./testsuite/e2e-linux/run.sh --inventory ... --extended
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/common.sh"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/inventory.sh"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/ssh.sh"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/podman_target.sh"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/transport.sh"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/pkg.sh"
# shellcheck source=/dev/null
source "$E2E_DIR/lib/artifacts.sh"

INVENTORY="${E2E_INVENTORY:-}"
SUITE_FILTER=""
RUN_EXTENDED=0
SKIP_PACKAGES=0
KEEP_GOING=0

usage() {
    cat <<EOF
Usage: $0 --inventory FILE [options]

Options:
  --inventory FILE     Host inventory (YAML)
  --backend ssh|podman Filter hosts by backend (also E2E_BACKEND)
  --suite NAME         Run suite(s): 01-install-server, 05-alerts-json-syslog, syscheck, ...
  --extended           Run default 01–05 then suites/syscheck/*
  --keep-going         Continue after suite host failures
  --keep               Keep Podman containers / remote scratch (E2E_KEEP=1)
  --no-build-packages  Do not auto-build missing RPM/Deb artifacts
  --build-packages     Force package build attempt before suites
  -h, --help           Show help

Environment:
  E2E_INVENTORY E2E_BACKEND E2E_PACKAGE_DIR E2E_BASE_PACKAGE
  E2E_TIMEOUT E2E_KEEP E2E_BUILD_PACKAGES E2E_KEEP_GOING
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --inventory) INVENTORY="$2"; shift 2 ;;
        --backend) E2E_BACKEND="$2"; export E2E_BACKEND; shift 2 ;;
        --suite) SUITE_FILTER="$2"; shift 2 ;;
        --extended) RUN_EXTENDED=1; shift ;;
        --keep-going) KEEP_GOING=1; E2E_KEEP_GOING=1; export E2E_KEEP_GOING; shift ;;
        --keep) E2E_KEEP=1; export E2E_KEEP; shift ;;
        --no-build-packages) E2E_BUILD_PACKAGES=0; export E2E_BUILD_PACKAGES; SKIP_PACKAGES=1; shift ;;
        --build-packages) E2E_BUILD_PACKAGES=1; export E2E_BUILD_PACKAGES; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$INVENTORY" ]] || die " --inventory is required (or set E2E_INVENTORY)"
[[ -f "$INVENTORY" ]] || die "inventory not found: $INVENTORY"
require_cmd python3

export E2E_KEEP_GOING="${E2E_KEEP_GOING:-$KEEP_GOING}"

log "inventory=$INVENTORY backend=${E2E_BACKEND:-all} package_dir=$E2E_PACKAGE_DIR"

if [[ "$SKIP_PACKAGES" != "1" ]]; then
    artifacts_ensure_for_inventory "$INVENTORY"
fi

select_suites() {
    suites=()
    if [[ "$RUN_EXTENDED" == "1" ]]; then
        mapfile -t suites < <(ls -1 "$E2E_DIR/suites"/[0-9]*.sh 2>/dev/null | sort)
        local _sk=()
        mapfile -t _sk < <(ls -1 "$E2E_DIR/suites/syscheck"/[0-9]*.sh 2>/dev/null | sort)
        suites+=("${_sk[@]+"${_sk[@]}"}")
        return 0
    fi
    if [[ -z "$SUITE_FILTER" ]]; then
        mapfile -t suites < <(ls -1 "$E2E_DIR/suites"/[0-9]*.sh | sort)
        return 0
    fi
    case "$SUITE_FILTER" in
        syscheck|extended-syscheck)
            mapfile -t suites < <(ls -1 "$E2E_DIR/suites/syscheck"/[0-9]*.sh | sort)
            ;;
        *)
            local match=""
            match=$(ls -1 "$E2E_DIR/suites"/${SUITE_FILTER}*.sh 2>/dev/null | head -1 || true)
            [[ -n "$match" ]] || match=$(ls -1 "$E2E_DIR/suites/syscheck"/${SUITE_FILTER}*.sh 2>/dev/null | head -1 || true)
            [[ -n "$match" ]] || match=$(ls -1 "$E2E_DIR/suites"/*${SUITE_FILTER}*.sh 2>/dev/null | head -1 || true)
            [[ -n "$match" ]] || match=$(ls -1 "$E2E_DIR/suites/syscheck"/*${SUITE_FILTER}*.sh 2>/dev/null | head -1 || true)
            [[ -n "$match" ]] || die "no suite matching '$SUITE_FILTER'"
            suites+=("$match")
            ;;
    esac
}

select_suites
((${#suites[@]} > 0)) || die "no suites selected"

for suite in "${suites[@]}"; do
    log "-------- running $(basename "$(dirname "$suite")")/$(basename "$suite") --------"
    bash "$suite" "$INVENTORY"
done

log "E2E finished successfully"
