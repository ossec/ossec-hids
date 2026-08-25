#!/usr/bin/env bash
# 01 — install OSSEC server on inventoried server hosts.
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/common.sh"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/inventory.sh"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/ssh.sh"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/podman_target.sh"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/transport.sh"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/pkg.sh"
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/assert.sh"

INVENTORY="${1:?inventory required}"
BACKEND_FILTER="${E2E_BACKEND:-}"
KEEP_GOING="${E2E_KEEP_GOING:-0}"
failed=0

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"
        continue
    fi
    log "=== 01-install-server: $name ($HOST_BACKEND/$HOST_FAMILY) ==="
    if ! (
        transport_prepare
        pkg_install_role server
        pkg_start_ossec
        sleep 3
        assert_server_daemons
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "01-install-server failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "01-install-server had failures"
log "01-install-server: all server hosts OK"
