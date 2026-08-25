#!/usr/bin/env bash
# Build / locate installable artifacts on the controller.

artifacts_ensure_source_tarball() {
    local out="$E2E_PACKAGE_DIR/ossec-hids-e2e-src.tar.gz"
    if [[ -f "$out" && "${E2E_FORCE_TARBALL:-0}" != "1" ]]; then
        # Refresh if older than 1 hour relative to install.sh mtime is complex; always rebuild lightly.
        :
    fi
    log "creating source tarball $out" >&2
    mkdir -p "$E2E_PACKAGE_DIR"
    tar -czf "$out" \
        --exclude='.git' \
        --exclude='testsuite/*.rpm' \
        --exclude='testsuite/*.deb' \
        --exclude='testsuite/*.tar.gz' \
        --exclude='src/external/pcre2-10.32' \
        --exclude='src/external/*.tar.gz' \
        -C "$ROOT_DIR" \
        --transform 's,^\./,ossec-hids/,' \
        .
    echo "$out"
}

artifacts_build_rpm_rocky10() {
    require_cmd mock
    require_cmd rpmbuild
    log "building SRPM"
    (cd "$ROOT_DIR" && ./testsuite/build-srpm.sh)
    local srpm
    srpm=$(ls -1t "$TESTSUITE_DIR"/ossec-hids-*.src.rpm 2>/dev/null | head -1)
    [[ -n "$srpm" ]] || die "no SRPM produced"
    log "mock rebuild rocky-10-x86_64 from $(basename "$srpm")"
    local resultdir="$E2E_DIR/mock-rocky10"
    mkdir -p "$resultdir"
    mock -r rocky-10-x86_64 --resultdir="$resultdir" --rebuild "$srpm"
    find "$resultdir" -maxdepth 1 -name 'ossec-hids*.rpm' ! -name '*.src.rpm' -exec cp -f {} "$E2E_PACKAGE_DIR/" \;
    log "RPM artifacts in $E2E_PACKAGE_DIR:"
    ls -1 "$E2E_PACKAGE_DIR"/ossec-hids*.rpm 2>/dev/null | grep -v src || true
}

artifacts_build_deb() {
    local which="${1:-all}"
    (cd "$ROOT_DIR" && ./testsuite/build-deb.sh "$which")
}

artifacts_ensure_for_inventory() {
    local inventory="$1"
    local need_rpm=0 need_deb=0
    local name family
    while read -r name; do
        [[ -z "$name" ]] && continue
        family=$(inventory_get_field "$inventory" "$name" family)
        case "$family" in
            rpm) need_rpm=1 ;;
            deb) need_deb=1 ;;
        esac
    done < <(inventory_list_hosts "$inventory" "${E2E_BACKEND:-}")

    if [[ "$need_rpm" == "1" ]]; then
        if ! pkg_find_rpm server >/dev/null 2>&1 && ! pkg_find_rpm agent >/dev/null 2>&1; then
            if [[ "${E2E_BUILD_PACKAGES:-1}" == "1" ]]; then
                artifacts_build_rpm_rocky10
            else
                warn "no RPM packages found; suites will use source install"
            fi
        fi
    fi
    if [[ "$need_deb" == "1" ]]; then
        if ! pkg_find_deb server >/dev/null 2>&1 && ! pkg_find_deb agent >/dev/null 2>&1; then
            if [[ "${E2E_BUILD_PACKAGES:-1}" == "1" ]]; then
                artifacts_build_deb all
            else
                warn "no Deb packages found; suites will use source install"
            fi
        fi
    fi
}
