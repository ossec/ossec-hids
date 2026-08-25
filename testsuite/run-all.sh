#!/usr/bin/env bash
# Run compile matrix, then Linux E2E on success.
# Usage (repo root):
#   ./testsuite/run-all.sh [build-test args...] -- [e2e-linux/run.sh args...]
#   ./testsuite/run-all.sh --inventory testsuite/e2e-linux/inventory.community.yaml --backend ssh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILD_ARGS=()
E2E_ARGS=()
seen_e2e=0

# Arguments before the first E2E-only flag go to build-test if they look like distro names;
# once we see --inventory/--backend/--suite/etc, remaining args go to e2e.
for arg in "$@"; do
    if [[ "$seen_e2e" -eq 1 ]]; then
        E2E_ARGS+=("$arg")
        continue
    fi
    case "$arg" in
        --)
            seen_e2e=1
            ;;
        --inventory|--backend|--suite|--keep|--keep-going|--no-build-packages|--build-packages)
            seen_e2e=1
            E2E_ARGS+=("$arg")
            ;;
        --inventory=*|--backend=*|--suite=*)
            seen_e2e=1
            E2E_ARGS+=("$arg")
            ;;
        *)
            if [[ "$arg" == -* && "$seen_e2e" -eq 0 ]]; then
                # Unknown dash arg: treat as E2E
                seen_e2e=1
                E2E_ARGS+=("$arg")
            else
                BUILD_ARGS+=("$arg")
            fi
            ;;
    esac
done

echo "[run-all] compile: ./testsuite/build-test/build.sh ${BUILD_ARGS[*]:-}"
(cd "$ROOT_DIR" && ./testsuite/build-test/build.sh "${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}")

if ((${#E2E_ARGS[@]} == 0)); then
    echo "[run-all] no E2E args; skipping e2e-linux (pass --inventory ... to run)"
    exit 0
fi

echo "[run-all] e2e: ./testsuite/e2e-linux/run.sh ${E2E_ARGS[*]}"
(cd "$ROOT_DIR" && ./testsuite/e2e-linux/run.sh "${E2E_ARGS[@]}")
