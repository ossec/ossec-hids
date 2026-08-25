#!/usr/bin/env bash
# Inventory loading (YAML → shell-friendly exports).
# Requires python3 + PyYAML on the controller.

inventory_list_hosts() {
    local inventory="$1"
    local backend_filter="${2:-}"
    local role_filter="${3:-}"
    python3 - "$inventory" "$backend_filter" "$role_filter" <<'PY'
import sys, yaml
path, backend, role = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    data = yaml.safe_load(f) or {}
hosts = data.get("hosts") or []
for h in hosts:
    if backend and h.get("backend") != backend:
        continue
    if role and h.get("role") != role:
        continue
    name = h.get("name") or ""
    if not name:
        continue
    print(name)
PY
}

inventory_get_field() {
    local inventory="$1" name="$2" field="$3"
    python3 - "$inventory" "$name" "$field" <<'PY'
import sys, yaml
path, name, field = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    data = yaml.safe_load(f) or {}
for h in data.get("hosts") or []:
    if h.get("name") == name:
        val = h.get(field, "")
        if val is None:
            val = ""
        if isinstance(val, bool):
            print("true" if val else "false")
        else:
            print(val)
        break
else:
    sys.exit(1)
PY
}

# Load host fields into HOST_* globals for the current target.
host_load() {
    local inventory="$1" name="$2"
    HOST_NAME="$name"
    HOST_BACKEND="$(inventory_get_field "$inventory" "$name" backend)"
    HOST_ROLE="$(inventory_get_field "$inventory" "$name" role)"
    HOST_FAMILY="$(inventory_get_field "$inventory" "$name" family)"
    HOST_DISTRO="$(inventory_get_field "$inventory" "$name" distro || true)"
    HOST_SSH="$(inventory_get_field "$inventory" "$name" ssh || true)"
    HOST_IMAGE="$(inventory_get_field "$inventory" "$name" image || true)"
    HOST_CONTAINER="$(inventory_get_field "$inventory" "$name" container || true)"
    HOST_SERVER="$(inventory_get_field "$inventory" "$name" server || true)"
    HOST_REQUIRES="$(inventory_get_field "$inventory" "$name" requires || true)"
    if [[ -z "${HOST_CONTAINER:-}" && "$HOST_BACKEND" == "podman" ]]; then
        HOST_CONTAINER="e2e-${HOST_NAME}"
    fi
    case "$HOST_BACKEND" in
        ssh|podman) ;;
        *) die "host $name: unknown backend '$HOST_BACKEND'" ;;
    esac
    case "$HOST_FAMILY" in
        rpm|deb) ;;
        *) die "host $name: family must be rpm or deb (got '$HOST_FAMILY')" ;;
    esac
    case "$HOST_ROLE" in
        server|agent) ;;
        *) die "host $name: role must be server or agent (got '$HOST_ROLE')" ;;
    esac
}

host_requires_vm() {
    [[ "${HOST_REQUIRES:-}" == "vm" ]]
}
