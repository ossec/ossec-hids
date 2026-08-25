#!/usr/bin/env bash
# 02 — install OSSEC agent and enroll against a server host.
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
# shellcheck source=/dev/null
source "$SUITE_DIR/../lib/enroll.sh"

INVENTORY="${1:?inventory required}"
BACKEND_FILTER="${E2E_BACKEND:-}"
KEEP_GOING="${E2E_KEEP_GOING:-0}"
failed=0

mapfile -t SERVERS < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)
if ((${#SERVERS[@]} == 0)); then
    # Allow agent backend filter while server is on another backend (e.g. community SSH).
    mapfile -t SERVERS < <(inventory_list_hosts "$INVENTORY" "" server)
fi
((${#SERVERS[@]} > 0)) || die "02-install-agent: no server hosts in inventory"
SERVER_NAME="${SERVERS[0]}"

# Resolve server address without clobbering later agent context permanently
host_load "$INVENTORY" "$SERVER_NAME"
transport_prepare
if [[ -n "${HOST_SERVER_OVERRIDE:-}" ]]; then
    SERVER_ADDR="$HOST_SERVER_OVERRIDE"
else
    # Prefer explicit inventory server= on agents; else transport address of first server
    SERVER_ADDR="$(transport_address)"
fi
log "using server $SERVER_NAME at $SERVER_ADDR"

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"
        continue
    fi
    # Per-agent override: inventory field "server" may be an IP/hostname
    local_server_addr="$SERVER_ADDR"
    if [[ -n "${HOST_SERVER:-}" ]]; then
        local_server_addr="$HOST_SERVER"
    fi
    log "=== 02-install-agent: $name → $local_server_addr ==="
    if ! (
        transport_prepare
        pkg_install_role agent "$local_server_addr"
        enroll_agent_to_server "$INVENTORY" "$SERVER_NAME" "e2e-${name}" any
        sleep 3
        assert_agent_daemon
        # Connection evidence on manager
        host_load "$INVENTORY" "$SERVER_NAME"
        transport_prepare
        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "grep -F 'e2e-${name}' $OSSEC_DIR/logs/ossec.log >/dev/null \
                || $OSSEC_DIR/bin/manage_agents -l 2>/dev/null | grep -F 'e2e-${name}' >/dev/null"; then
                _ok=1
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= E2E_TIMEOUT )); then
                break
            fi
            sleep 2
        done
        [[ "$_ok" -eq 1 ]] || die "agent e2e-${name} not observed on server"
        log "OK: server saw agent activity for e2e-${name}"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "02-install-agent failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" agent)

[[ "$failed" -eq 0 ]] || die "02-install-agent had failures"
log "02-install-agent: all agent hosts OK"
