#!/usr/bin/env bash
# 03 — feature smoke on server hosts (logtest + syscheck touch).
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
FIXTURES="$SUITE_DIR/../fixtures"
failed=0

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"
        continue
    fi
    log "=== 03-feature-smoke: $name ==="
    if ! (
        transport_prepare

        # Ensure server is up
        transport_bash "[[ -x $OSSEC_DIR/bin/ossec-control ]]"
        transport_bash "$OSSEC_DIR/bin/ossec-control status >/dev/null 2>&1 || $OSSEC_DIR/bin/ossec-control start"
        sleep 2

        # --- logtest fixture ---
        remote_fixture="$E2E_REMOTE_TMP/sshd-failed-login.log"
        transport_copy "$FIXTURES/sshd-failed-login.log" "$remote_fixture"
        assert_logtest_ok "$remote_fixture"

        # Feed into alerts via localfile if present; also append to a monitored path
        transport_bash "
            set -e
            mkdir -p /var/log
            touch /var/log/secure /var/log/auth.log 2>/dev/null || true
            cat $remote_fixture >> /var/log/secure 2>/dev/null || cat $remote_fixture >> /var/log/auth.log
        "

        # --- syscheck: isolate a tiny monitored tree so pre-scan finishes quickly ---
        watched="watched-$$-$(date +%s).txt"
        transport_bash "
            set -e
            mkdir -p /opt/e2e-syscheck
            echo baseline-\$(date +%s) > /opt/e2e-syscheck/$watched
            conf=$OSSEC_DIR/etc/ossec.conf
            [[ -f \$conf.bak.e2e-syscheck ]] || cp \$conf \$conf.bak.e2e-syscheck
            rm -f $OSSEC_DIR/queue/syscheck/syscheck $OSSEC_DIR/queue/syscheck/.syscheck.cpt
            # Stamp the log so we only match post-restart scan completion.
            echo \"E2E_SYSCHECK_MARK \$(date -Iseconds)\" >> $OSSEC_DIR/logs/ossec.log
            python3 - <<'PY'
from pathlib import Path
import re
p = Path('$OSSEC_DIR/etc/ossec.conf')
text = p.read_text()
block = '''  <syscheck>
    <frequency>30</frequency>
    <directories check_all=\"yes\" realtime=\"yes\">/opt/e2e-syscheck</directories>
  </syscheck>
'''
text2, n = re.subn(r'[ \\t]*<syscheck>.*?</syscheck>\\s*', '', text, flags=re.S)
if n == 0:
    text2 = text
text2 = re.sub(r'</ossec_config>', block + '</ossec_config>', text2, count=1)
p.write_text(text2)
PY
            $OSSEC_DIR/bin/ossec-control restart
        "

        # Wait for a Finished line that appears after our mark
        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "
                mark=\$(grep -n 'E2E_SYSCHECK_MARK' $OSSEC_DIR/logs/ossec.log | tail -1 | cut -d: -f1)
                [[ -n \"\$mark\" ]] || exit 1
                tail -n +\$mark $OSSEC_DIR/logs/ossec.log | grep -F 'Finished creating syscheck database' >/dev/null
                [[ -f $OSSEC_DIR/queue/syscheck/syscheck ]]
                grep -a 'opt/e2e-syscheck/$watched' $OSSEC_DIR/queue/syscheck/syscheck >/dev/null
            "; then
                _ok=1
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= E2E_TIMEOUT )); then
                break
            fi
            sleep 2
        done
        [[ "$_ok" -eq 1 ]] || die "syscheck pre-scan did not index /opt/e2e-syscheck/$watched"
        log "OK: syscheck database contains $watched"

        transport_bash "echo changed-\$(date +%s) > /opt/e2e-syscheck/$watched"

        # Hard-assert integrity alert (queue readiness remediated; no soft-pass).
        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "
                grep -E 'Rule: 550' -A8 $OSSEC_DIR/logs/alerts/alerts.log 2>/dev/null | grep -F '$watched' >/dev/null \
                || grep -Ei 'Integrity checksum changed' $OSSEC_DIR/logs/alerts/alerts.log 2>/dev/null | grep -F '$watched' >/dev/null
            "; then
                _ok=1
                log "OK: integrity alert observed for $watched"
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= E2E_TIMEOUT )); then
                break
            fi
            sleep 2
        done
        [[ "$_ok" -eq 1 ]] || die "syscheck smoke: rule 550 / integrity alert for $watched not observed"


        # Optional: csyslogd config parse / start if binary exists
        if transport_exec test -x "$OSSEC_DIR/bin/ossec-csyslogd"; then
            transport_bash "
                set -e
                conf=$OSSEC_DIR/etc/ossec.conf
                if ! grep -q '<syslog_output>' \$conf; then
                    cp \$conf \$conf.bak.csyslog
                    awk '
                        /<\/ossec_config>/ && !done {
                            print \"  <syslog_output>\"
                            print \"    <server>127.0.0.1</server>\"
                            print \"    <port>514</port>\"
                            print \"    <level>5</level>\"
                            print \"  </syslog_output>\"
                            done=1
                        }
                        { print }
                    ' \$conf.bak.csyslog > \$conf
                    $OSSEC_DIR/bin/ossec-control restart
                    sleep 3
                fi
                pgrep -x ossec-csyslogd >/dev/null
            " && log "OK: ossec-csyslogd running" || warn "csyslogd smoke skipped/failed (non-fatal)"
        fi

        log "OK: feature smoke on $name"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "03-feature-smoke failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "03-feature-smoke had failures"
log "03-feature-smoke: all server hosts OK"
