#!/usr/bin/env bash
# Package / source install helpers via transport_*.

pkg_find_rpm() {
    local role="$1" dir="${2:-$E2E_PACKAGE_DIR}"
    local base server agent
    base=$(ls -1 "$dir"/ossec-hids-[0-9]*.rpm 2>/dev/null | grep -v '\.src\.rpm$' | grep -Ev 'agent|server|hybrid|mysql|postgres' | sort | tail -1 || true)
    server=$(ls -1 "$dir"/ossec-hids-server-*.rpm 2>/dev/null | sort | tail -1 || true)
    agent=$(ls -1 "$dir"/ossec-hids-agent-*.rpm 2>/dev/null | sort | tail -1 || true)
    case "$role" in
        server)
            [[ -n "$base" && -n "$server" ]] || return 1
            printf '%s\n%s\n' "$base" "$server"
            ;;
        agent)
            [[ -n "$base" && -n "$agent" ]] || return 1
            printf '%s\n%s\n' "$base" "$agent"
            ;;
        *) return 1 ;;
    esac
}

pkg_find_deb() {
    local role="$1" dir="${2:-$E2E_PACKAGE_DIR}"
    local deb
    case "$role" in
        server)
            deb=$(ls -1 "$dir"/ossec-hids_*.deb 2>/dev/null | grep -v agent | sort | tail -1 || true)
            ;;
        agent)
            deb=$(ls -1 "$dir"/ossec-hids-agent_*.deb 2>/dev/null | sort | tail -1 || true)
            ;;
        *) return 1 ;;
    esac
    [[ -n "$deb" ]] || return 1
    printf '%s\n' "$deb"
}

pkg_stop_ossec() {
    transport_bash "
        if [[ -x $OSSEC_DIR/bin/ossec-control ]]; then
            $OSSEC_DIR/bin/ossec-control stop || true
        fi
        systemctl stop ossec-hids ossec-hids-authd 2>/dev/null || true
    " || true
}

pkg_uninstall() {
    case "$HOST_FAMILY" in
        rpm)
            transport_bash '
                if command -v dnf >/dev/null 2>&1; then
                    dnf -y remove "ossec-hids*" 2>/dev/null || true
                elif command -v yum >/dev/null 2>&1; then
                    yum -y remove "ossec-hids*" 2>/dev/null || true
                fi
                rpm -qa "ossec-hids*" | xargs -r rpm -e --nodeps 2>/dev/null || true
            ' || true
            ;;
        deb)
            transport_bash '
                export DEBIAN_FRONTEND=noninteractive
                apt-get -y remove --purge ossec-hids ossec-hids-agent 2>/dev/null || true
                dpkg -l "ossec-hids*" 2>/dev/null | awk "/^ii/ {print \$2}" | xargs -r dpkg --purge || true
            ' || true
            ;;
    esac
}

pkg_install_files() {
    local remote_dir="$E2E_REMOTE_TMP/pkgs"
    transport_exec mkdir -p "$remote_dir"
    local f remote_files=()
    for f in "$@"; do
        [[ -f "$f" ]] || die "package not found: $f"
        local base
        base=$(basename "$f")
        log "copying $base → $HOST_NAME:$remote_dir/"
        transport_copy "$f" "$remote_dir/$base"
        remote_files+=("$remote_dir/$base")
    done

    case "$HOST_FAMILY" in
        rpm)
            transport_bash "
                set -e
                dnf -y install ${remote_files[*]} || rpm -Uvh --force ${remote_files[*]}
            "
            ;;
        deb)
            transport_bash "
                set -e
                export DEBIAN_FRONTEND=noninteractive
                # Ensure OSSEC users/groups exist before package configure
                getent group ossec >/dev/null || groupadd -r ossec
                getent group ossecr >/dev/null || groupadd -r ossecr
                getent passwd ossec >/dev/null || useradd -r -g ossec -d /var/ossec -s /sbin/nologin ossec
                getent passwd ossecr >/dev/null || useradd -r -g ossecr -d /var/ossec -s /sbin/nologin ossecr
                getent passwd ossecm >/dev/null || useradd -r -g ossec -d /var/ossec -s /sbin/nologin ossecm
                apt-get -qq update || true
                apt-get -y install ${remote_files[*]} || dpkg -i ${remote_files[*]}
                dpkg --configure -a || true
                apt-get -y -f install || true
            "
            ;;
    esac
}

pkg_write_preloaded() {
    local role="$1" server_ip="${2:-}"
    local tmp
    if [[ "$role" == "agent" && -z "$server_ip" ]]; then
        die "pkg_write_preloaded: agent role requires a server IP"
    fi
    tmp=$(mktemp)
    cat >"$tmp" <<EOF
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="$role"
USER_DIR="$OSSEC_DIR"
USER_DELETE_DIR="y"
USER_ENABLE_ACTIVE_RESPONSE="n"
USER_ENABLE_SYSCHECK="y"
USER_ENABLE_ROOTCHECK="n"
USER_UPDATE_RULES="y"
USER_ENABLE_EMAIL="n"
USER_ENABLE_SYSLOG="n"
USER_ENABLE_FIREWALL_RESPONSE="n"
EOF
    if [[ "$role" == "agent" && -n "$server_ip" ]]; then
        echo "USER_AGENT_SERVER_IP=\"$server_ip\"" >>"$tmp"
    fi
    echo "$tmp"
}

pkg_source_install() {
    local role="$1" server_ip="${2:-}"
    local tarball preloaded remote_tgz remote_preload
    tarball=$(artifacts_ensure_source_tarball)
    preloaded=$(pkg_write_preloaded "$role" "$server_ip")
    remote_tgz="$E2E_REMOTE_TMP/ossec-src.tar.gz"
    remote_preload="$E2E_REMOTE_TMP/preloaded-vars.conf"

    log "source-install $role on $HOST_NAME"
    transport_copy "$tarball" "$remote_tgz"
    transport_copy "$preloaded" "$remote_preload"
    rm -f "$preloaded"

    case "$HOST_FAMILY" in
        rpm)
            transport_bash '
                set -e
                if command -v dnf >/dev/null 2>&1; then
                    dnf -y install gcc make openssl-devel pcre2-devel zlib-devel \
                        systemd-devel file-devel libcurl-devel tar gzip findutils \
                        2>/dev/null || dnf -y install gcc make openssl-devel pcre2-devel zlib-devel tar gzip
                fi
            '
            ;;
        deb)
            transport_bash '
                set -e
                export DEBIAN_FRONTEND=noninteractive
                apt-get -qq update
                apt-get -y install build-essential libssl-dev libpcre2-dev zlib1g-dev \
                    libsystemd-dev libmagic-dev libcurl4-openssl-dev tar gzip
            '
            ;;
    esac

    transport_bash "
        set -e
        rm -rf $E2E_REMOTE_TMP/src
        mkdir -p $E2E_REMOTE_TMP/src
        tar -xzf $remote_tgz -C $E2E_REMOTE_TMP/src --strip-components=1
        cp $remote_preload $E2E_REMOTE_TMP/src/etc/preloaded-vars.conf
        cd $E2E_REMOTE_TMP/src
        ./install.sh
    "
}

pkg_install_role() {
    local role="$1" server_ip="${2:-}"
    pkg_stop_ossec
    local files=()
    case "$HOST_FAMILY" in
        rpm)
            mapfile -t files < <(pkg_find_rpm "$role" || true)
            ;;
        deb)
            mapfile -t files < <(pkg_find_deb "$role" || true)
            ;;
    esac

    if ((${#files[@]} > 0)); then
        log "installing $role packages on $HOST_NAME: ${files[*]}"
        pkg_uninstall
        pkg_install_files "${files[@]}"
    else
        warn "no $HOST_FAMILY packages for role=$role in $E2E_PACKAGE_DIR; falling back to source install"
        pkg_uninstall
        pkg_source_install "$role" "$server_ip"
    fi

    if [[ "$role" == "agent" && -n "$server_ip" ]]; then
        # Ensure server IP is set even for package installs.
        transport_bash "
            set -e
            conf=$OSSEC_DIR/etc/ossec.conf
            if [[ -f \$conf ]]; then
                if grep -q '<server-ip>' \$conf; then
                    sed -i 's#<server-ip>.*</server-ip>#<server-ip>$server_ip</server-ip>#' \$conf
                elif grep -q '<address>' \$conf; then
                    sed -i 's#<address>.*</address>#<address>$server_ip</address>#' \$conf
                fi
            fi
        "
    fi
}

pkg_sanitize_config() {
    # Package defaults often enable email with placeholder SMTP; disable for E2E.
    # Remoted requires a non-empty client.keys file.
    transport_bash "
        set -e
        conf=$OSSEC_DIR/etc/ossec.conf
        [[ -f \$conf ]] || exit 0
        sed -i 's#<email_notification>yes</email_notification>#<email_notification>no</email_notification>#' \$conf
        sed -i 's#<smtp_server>smtp.example.com.</smtp_server>#<smtp_server>127.0.0.1</smtp_server>#' \$conf || true
        mkdir -p $OSSEC_DIR/etc $OSSEC_DIR/logs/alerts $OSSEC_DIR/logs/archives $OSSEC_DIR/logs/firewall $OSSEC_DIR/queue/alerts $OSSEC_DIR/queue/ossec
        if [[ ! -s $OSSEC_DIR/etc/client.keys ]]; then
            touch $OSSEC_DIR/etc/client.keys
            chown root:ossec $OSSEC_DIR/etc/client.keys 2>/dev/null || true
            chmod 640 $OSSEC_DIR/etc/client.keys 2>/dev/null || true
            if [[ -x $OSSEC_DIR/bin/manage_agents ]]; then
                printf 'any,e2e-placeholder\n' | $OSSEC_DIR/bin/manage_agents -f - >/dev/null || true
            fi
        fi
        touch /var/log/secure /var/log/messages /var/log/maillog 2>/dev/null || true
    "
}

pkg_start_ossec() {
    pkg_sanitize_config
    transport_bash "
        set -e
        if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files ossec-hids.service >/dev/null 2>&1; then
            systemctl enable ossec-hids >/dev/null 2>&1 || true
            systemctl stop ossec-hids >/dev/null 2>&1 || true
        fi
        $OSSEC_DIR/bin/ossec-control start
    "
}

pkg_restart_ossec() {
    pkg_sanitize_config
    # Prefer stop/start over restart — analysisd can abort mid-join on restart.
    transport_bash "
        set -e
        $OSSEC_DIR/bin/ossec-control stop || true
        sleep 3
        # Clear stale sockets that confuse a fresh analysisd
        rm -f $OSSEC_DIR/queue/ossec/queue $OSSEC_DIR/queue/alerts/ar $OSSEC_DIR/queue/alerts/execq 2>/dev/null || true
        mkdir -p $OSSEC_DIR/queue/ossec $OSSEC_DIR/queue/alerts
        chown ossec:ossec $OSSEC_DIR/queue/ossec $OSSEC_DIR/queue/alerts 2>/dev/null || true
        $OSSEC_DIR/bin/ossec-control start
        sleep 2
        # analysisd must stay alive (no immediate abort)
        pgrep -x ossec-analysisd >/dev/null
        pgrep -x ossec-syscheckd >/dev/null
    "
}
