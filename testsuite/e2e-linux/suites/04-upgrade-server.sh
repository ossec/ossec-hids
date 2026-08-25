#!/usr/bin/env bash
# 04 — upgrade server: BASE_PACKAGE (or prior install) → current artifact.
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
source "$SUITE_DIR/../lib/artifacts.sh"

INVENTORY="${1:?inventory required}"
BACKEND_FILTER="${E2E_BACKEND:-}"
KEEP_GOING="${E2E_KEEP_GOING:-0}"
BASE_PACKAGE="${E2E_BASE_PACKAGE:-}"
failed=0

install_base() {
    if [[ -z "$BASE_PACKAGE" ]]; then
        log "E2E_BASE_PACKAGE unset: installing current packages as baseline, then reinstalling (upgrade simulation)"
        pkg_install_role server
        pkg_start_ossec
        sleep 2
        transport_bash "
            set -e
            conf=$OSSEC_DIR/etc/ossec.conf
            grep -q 'e2e-upgrade-marker' \$conf || \
              sed -i 's#</ossec_config>#  <!-- e2e-upgrade-marker -->\n</ossec_config>#' \$conf
            id ossec >/dev/null
        "
        return 0
    fi

    local remote="$E2E_REMOTE_TMP/base-pkgs"
    transport_exec mkdir -p "$remote"
    if [[ -d "$BASE_PACKAGE" ]]; then
        local f
        for f in "$BASE_PACKAGE"/ossec-hids*.rpm "$BASE_PACKAGE"/ossec-hids*.deb; do
            [[ -f "$f" ]] || continue
            transport_copy "$f" "$remote/$(basename "$f")"
        done
    elif [[ -f "$BASE_PACKAGE" ]]; then
        transport_copy "$BASE_PACKAGE" "$remote/$(basename "$BASE_PACKAGE")"
    else
        die "E2E_BASE_PACKAGE not found: $BASE_PACKAGE"
    fi

    pkg_stop_ossec
    pkg_uninstall
    case "$HOST_FAMILY" in
        rpm)
            transport_bash "set -e; dnf -y install $remote/ossec-hids*.rpm || rpm -Uvh $remote/ossec-hids*.rpm"
            ;;
        deb)
            transport_bash "set -e; export DEBIAN_FRONTEND=noninteractive; dpkg -i $remote/ossec-hids*.deb || apt-get -y -f install"
            ;;
    esac
    pkg_start_ossec
    transport_bash "
        set -e
        conf=$OSSEC_DIR/etc/ossec.conf
        grep -q 'e2e-upgrade-marker' \$conf || \
          sed -i 's#</ossec_config>#  <!-- e2e-upgrade-marker -->\n</ossec_config>#' \$conf
    "
}

upgrade_current() {
    local files=()
    case "$HOST_FAMILY" in
        rpm) mapfile -t files < <(pkg_find_rpm server || true) ;;
        deb) mapfile -t files < <(pkg_find_deb server || true) ;;
    esac
    if ((${#files[@]} > 0)); then
        pkg_install_files "${files[@]}"
        return 0
    fi

    local tarball preloaded
    tarball=$(artifacts_ensure_source_tarball)
    preloaded=$(pkg_write_preloaded server)
    echo 'USER_UPDATE="y"' >>"$preloaded"
    echo 'USER_DELETE_DIR="n"' >>"$preloaded"
    transport_copy "$tarball" "$E2E_REMOTE_TMP/ossec-src.tar.gz"
    transport_copy "$preloaded" "$E2E_REMOTE_TMP/preloaded-vars.conf"
    rm -f "$preloaded"
    transport_bash "
        set -e
        rm -rf $E2E_REMOTE_TMP/src
        mkdir -p $E2E_REMOTE_TMP/src
        tar -xzf $E2E_REMOTE_TMP/ossec-src.tar.gz -C $E2E_REMOTE_TMP/src --strip-components=1
        cp $E2E_REMOTE_TMP/preloaded-vars.conf $E2E_REMOTE_TMP/src/etc/preloaded-vars.conf
        cd $E2E_REMOTE_TMP/src
        ./install.sh
    "
}

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"
        continue
    fi
    log "=== 04-upgrade-server: $name ==="
    if ! (
        transport_prepare
        install_base
        assert_server_daemons

        log "upgrading to current artifact on $name"
        upgrade_current
        pkg_restart_ossec
        sleep 3
        assert_server_daemons

        transport_bash "
            set -e
            grep -q 'e2e-upgrade-marker' $OSSEC_DIR/etc/ossec.conf
            id ossec >/dev/null
        "
        log "OK: upgrade preserved config marker and users on $name"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "04-upgrade-server failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "04-upgrade-server had failures"
log "04-upgrade-server: all server hosts OK"
