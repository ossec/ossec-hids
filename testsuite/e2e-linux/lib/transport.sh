#!/usr/bin/env bash
# Backend-agnostic transport: uses HOST_* globals from inventory.sh.

transport_prepare() {
    case "$HOST_BACKEND" in
        ssh)
            require_cmd ssh
            require_cmd scp
            [[ -n "${HOST_SSH:-}" ]] || die "host $HOST_NAME: ssh field required"
            log "probing SSH $HOST_SSH"
            ssh_probe "$HOST_SSH" || die "cannot SSH to $HOST_SSH"
            ;;
        podman)
            require_cmd podman
            [[ -n "${HOST_IMAGE:-}" ]] || die "host $HOST_NAME: image field required"
            podman_start_target "$HOST_CONTAINER" "$HOST_IMAGE"
            ;;
    esac
    transport_exec mkdir -p "$E2E_REMOTE_TMP"
}

transport_cleanup() {
    case "$HOST_BACKEND" in
        podman)
            podman_stop_target "$HOST_CONTAINER"
            ;;
        ssh)
            # Leave dedicated hosts running; only clear remote scratch if not keeping.
            if [[ "${E2E_KEEP}" != "1" ]]; then
                transport_exec rm -rf "$E2E_REMOTE_TMP" || true
            fi
            ;;
    esac
}

transport_exec() {
    case "$HOST_BACKEND" in
        ssh) ssh_exec "$HOST_SSH" "$@" ;;
        podman) podman_exec "$HOST_CONTAINER" "$@" ;;
        *) die "transport_exec: no HOST_BACKEND" ;;
    esac
}

# Run a remote shell snippet as root (or via sudo on non-root SSH).
transport_bash() {
    local script="$1"
    case "$HOST_BACKEND" in
        ssh)
            if [[ "$HOST_SSH" == root@* ]]; then
                ssh_exec "$HOST_SSH" bash -s <<<"$script"
            else
                ssh_exec "$HOST_SSH" sudo -n bash -s <<<"$script"
            fi
            ;;
        podman)
            podman_exec "$HOST_CONTAINER" bash -c "$script"
            ;;
    esac
}

transport_copy() {
    local src="$1" dest="$2"
    case "$HOST_BACKEND" in
        ssh) ssh_copy "$src" "$HOST_SSH" "$dest" ;;
        podman) podman_copy "$src" "$HOST_CONTAINER" "$dest" ;;
    esac
}

# Resolve a reachable address for this host (agents use this as server IP).
transport_address() {
    case "$HOST_BACKEND" in
        ssh)
            # user@host → host (IP or DNS)
            echo "${HOST_SSH#*@}"
            ;;
        podman)
            podman inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HOST_CONTAINER" \
                | awk 'NF{print; exit}'
            ;;
    esac
}
