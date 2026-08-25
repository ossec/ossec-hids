#!/usr/bin/env bash
# Podman systemd target lifecycle + exec/copy.

podman_ensure_network() {
    if ! podman network exists "$E2E_PODMAN_NETWORK" >/dev/null 2>&1; then
        log "creating podman network $E2E_PODMAN_NETWORK"
        podman network create "$E2E_PODMAN_NETWORK" >/dev/null
    fi
}

podman_ensure_image() {
    local image="$1"
    if podman image exists "$image" >/dev/null 2>&1; then
        return 0
    fi
    # Also accept short name without localhost/ prefix
    local short="${image#localhost/}"
    if [[ "$short" != "$image" ]] && podman image exists "$short" >/dev/null 2>&1; then
        podman tag "$short" "$image" 2>/dev/null || true
        return 0
    fi
    case "$image" in
        localhost/ossec-e2e-rocky10|ossec-e2e-rocky10)
            log "building Podman image $image"
            podman build -t ossec-e2e-rocky10 -t localhost/ossec-e2e-rocky10 "$E2E_DIR/images/rocky10"
            ;;
        localhost/ossec-e2e-ubuntu2404|ossec-e2e-ubuntu2404)
            log "building Podman image $image"
            podman build -t ossec-e2e-ubuntu2404 -t localhost/ossec-e2e-ubuntu2404 "$E2E_DIR/images/ubuntu2404"
            ;;
        *)
            log "pulling Podman image $image"
            podman pull "$image"
            ;;
    esac
}

podman_start_target() {
    local name="$1" image="$2"
    require_cmd podman
    podman_ensure_network
    podman_ensure_image "$image"

    if podman container exists "$name" >/dev/null 2>&1; then
        local state
        state=$(podman inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
        if [[ "$state" != "running" ]]; then
            log "starting existing container $name"
            podman start "$name" >/dev/null
        fi
    else
        log "creating systemd container $name from $image"
        podman run -d \
            --name "$name" \
            --hostname "$name" \
            --network "$E2E_PODMAN_NETWORK" \
            --systemd=always \
            --tmpfs /run \
            --tmpfs /tmp \
            -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
            "$image"
    fi

    wait_for "systemd in $name" 90 bash -c \
        "st=\$(podman exec '$name' systemctl is-system-running 2>/dev/null || true); [[ \"\$st\" == running || \"\$st\" == degraded ]]"
}

podman_stop_target() {
    local name="$1"
    if [[ "${E2E_KEEP}" == "1" ]]; then
        log "keeping container $name (E2E_KEEP=1)"
        return 0
    fi
    if podman container exists "$name" >/dev/null 2>&1; then
        log "removing container $name"
        podman rm -f "$name" >/dev/null
    fi
}

podman_exec() {
    local name="$1"
    shift
    podman exec "$name" "$@"
}

podman_copy() {
    local src="$1" name="$2" dest="$3"
    podman cp "$src" "${name}:${dest}"
}

podman_probe() {
    local name="$1"
    podman exec "$name" true
}
