#!/usr/bin/env bash
# SSH transport helpers.

ssh_opts() {
    echo -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15
}

ssh_exec() {
    local target="$1"
    shift
    # shellcheck disable=SC2046
    ssh $(ssh_opts) "$target" "$@"
}

ssh_sudo() {
    local target="$1"
    shift
    if [[ "$target" == root@* ]]; then
        ssh_exec "$target" "$@"
    else
        ssh_exec "$target" sudo -n bash -s <<<"$(printf '%q ' "$@")"
    fi
}

ssh_copy() {
    local src="$1" target="$2" dest="$3"
    # shellcheck disable=SC2046
    scp $(ssh_opts) -q "$src" "${target}:${dest}"
}

ssh_probe() {
    local target="$1"
    ssh_exec "$target" true
}
