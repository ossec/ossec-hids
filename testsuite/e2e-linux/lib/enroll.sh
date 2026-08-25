#!/usr/bin/env bash
# Enroll agent against a prepared server host.
# Uses manage_agents bulk load on the server, then copies the client.keys line to the agent.

enroll_agent_to_server() {
    local server_inventory="$1"
    local server_name="$2"
    local agent_name="${3:-e2e-agent}"
    local agent_ip="${4:-any}"

    # Save agent host context
    local A_NAME="$HOST_NAME" A_BACKEND="$HOST_BACKEND" A_SSH="${HOST_SSH:-}" \
          A_CONTAINER="${HOST_CONTAINER:-}" A_FAMILY="$HOST_FAMILY" A_ROLE="$HOST_ROLE" \
          A_IMAGE="${HOST_IMAGE:-}" A_DISTRO="${HOST_DISTRO:-}"

    host_load "$server_inventory" "$server_name"
    transport_prepare

    local keyline keyfile
    keyfile=$(mktemp)
    transport_bash "
        set -e
        # Drop prior agent with same name
        if grep -E ' ${agent_name} ' $OSSEC_DIR/etc/client.keys >/dev/null 2>&1; then
            grep -vE ' ${agent_name} ' $OSSEC_DIR/etc/client.keys > $OSSEC_DIR/etc/client.keys.tmp || true
            mv $OSSEC_DIR/etc/client.keys.tmp $OSSEC_DIR/etc/client.keys
            chown root:ossec $OSSEC_DIR/etc/client.keys 2>/dev/null || true
            chmod 640 $OSSEC_DIR/etc/client.keys 2>/dev/null || true
        fi
        printf '%s,%s\n' '$agent_ip' '$agent_name' | $OSSEC_DIR/bin/manage_agents -f -
        grep -E ' ${agent_name} ' $OSSEC_DIR/etc/client.keys
        $OSSEC_DIR/bin/ossec-control restart || true
    " | tee "$keyfile"
    keyline=$(grep -E " ${agent_name} " "$keyfile" | tail -1 | tr -d '\r')
    rm -f "$keyfile"
    [[ -n "$keyline" ]] || die "failed to create agent key for $agent_name on $server_name"
    log "server key line: $keyline"

    # Restore agent context and install matching key
    HOST_NAME="$A_NAME" HOST_BACKEND="$A_BACKEND" HOST_SSH="$A_SSH" \
        HOST_CONTAINER="$A_CONTAINER" HOST_FAMILY="$A_FAMILY" HOST_ROLE="$A_ROLE" \
        HOST_IMAGE="$A_IMAGE" HOST_DISTRO="$A_DISTRO"

    transport_bash "
        set -e
        mkdir -p $OSSEC_DIR/etc
        printf '%s\n' '$keyline' > $OSSEC_DIR/etc/client.keys
        chown root:ossec $OSSEC_DIR/etc/client.keys 2>/dev/null || true
        chmod 640 $OSSEC_DIR/etc/client.keys 2>/dev/null || true
        $OSSEC_DIR/bin/ossec-control restart
    "
    log "OK: enrolled agent $agent_name to server $server_name"
}
