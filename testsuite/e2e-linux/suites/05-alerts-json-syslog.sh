#!/usr/bin/env bash
# 05 — JSON syslog_output forwards alerts.json (agent_name is a first-class field).
# Prints the alerts.json line and the captured syslog datagram.
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
JSON_PORT="${E2E_JSON_SYSLOG_PORT:-10514}"
failed=0

show_remote_outputs() {
    local token="$1"
    log "-------- alerts.json (matching ${token}) --------"
    transport_bash "
        set +e
        f=$OSSEC_DIR/logs/alerts/alerts.json
        if [[ -f \$f ]]; then
            grep -F $(printf '%q' "$token") \$f | tail -1
        else
            echo '(alerts.json not present)'
        fi
    " || true
    log "-------- JSON syslog datagram (matching ${token}) --------"
    transport_bash "
        set +e
        f=$E2E_REMOTE_TMP/json-syslog.out
        if [[ -f \$f ]]; then
            grep -F $(printf '%q' "$token") \$f | tail -1
        else
            echo '(no syslog capture file)'
        fi
    " || true
    log "-------- pretty JSON payload --------"
    transport_bash "
        set +e
        python3 - <<'PY'
import json, re, pathlib
token = '${token}'
paths = [
    pathlib.Path('$E2E_REMOTE_TMP/json-syslog.out'),
    pathlib.Path('$OSSEC_DIR/logs/alerts/alerts.json'),
]
raw = ''
for p in paths:
    if not p.is_file():
        continue
    for line in p.read_text(errors='replace').splitlines():
        if token in line:
            raw = line
    if raw:
        break
if not raw:
    print('(no matching line)')
    raise SystemExit(0)
m = re.search(r'ossec:\\s*(\\{.*\\})\\s*\$', raw)
blob = m.group(1) if m else raw
try:
    obj = json.loads(blob)
except json.JSONDecodeError:
    print(raw)
    raise SystemExit(0)
print(json.dumps(obj, indent=2, sort_keys=True))
print('--- field check ---')
print('agent_name=', obj.get('agent_name'))
rule = obj.get('rule') or {}
if isinstance(rule, dict):
    print('rule.sidid=', rule.get('sidid'))
    print('rule.level=', rule.get('level'))
PY
    " || true
}

while read -r name; do
    [[ -z "$name" ]] && continue
    host_load "$INVENTORY" "$name"
    if host_requires_vm && [[ "$HOST_BACKEND" == "podman" ]]; then
        log "skip $name (requires: vm)"
        continue
    fi
    log "=== 05-alerts-json-syslog: $name ==="
    if ! (
        transport_prepare

        transport_bash "[[ -x $OSSEC_DIR/bin/ossec-control ]]"
        transport_bash "[[ -x $OSSEC_DIR/bin/ossec-csyslogd ]]" \
            || die "ossec-csyslogd missing on $name (server package required)"

        token="e2ejson$(date +%s)"
        capture="$E2E_REMOTE_TMP/json-syslog.out"
        listener_pid_file="$E2E_REMOTE_TMP/json-syslog.pid"

        inject_log="$E2E_REMOTE_TMP/inject.log"

        transport_bash "
            set -e
            mkdir -p $E2E_REMOTE_TMP
            : > $capture
            : > $inject_log
            chmod 644 $inject_log
            if [[ -f $listener_pid_file ]]; then
                kill \$(cat $listener_pid_file) 2>/dev/null || true
                rm -f $listener_pid_file
            fi
            nohup python3 -u -c 'import socket, pathlib
port = int($JSON_PORT)
path = pathlib.Path(\"$capture\")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((\"127.0.0.1\", port))
sock.settimeout(1.0)
fh = path.open(\"ab\")
while True:
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        continue
    fh.write(data.replace(b\"\\n\", b\" \") + b\"\\n\")
    fh.flush()
' >/dev/null 2>&1 &
            echo \$! > $listener_pid_file
            disown \$(cat $listener_pid_file) 2>/dev/null || true
            sleep 0.3
            if ! kill -0 \$(cat $listener_pid_file) 2>/dev/null; then
                echo 'JSON syslog UDP listener failed to start (port ${JSON_PORT} in use?)' >&2
                exit 1
            fi
        "
        stop_json_listener() {
            transport_bash "
                if [[ -f $listener_pid_file ]]; then
                    kill \$(cat $listener_pid_file) 2>/dev/null || true
                    rm -f $listener_pid_file
                fi
            " || true
        }
        trap stop_json_listener EXIT

        transport_bash "
            set -e
            conf=$OSSEC_DIR/etc/ossec.conf
            [[ -f \$conf.bak.e2e-json-syslog ]] || cp \$conf \$conf.bak.e2e-json-syslog
            python3 - <<'PY'
from pathlib import Path
import re
p = Path('$OSSEC_DIR/etc/ossec.conf')
text = p.read_text()
if re.search(r'<jsonout_output>', text):
    text = re.sub(r'<jsonout_output>.*?</jsonout_output>',
                  '<jsonout_output>yes</jsonout_output>', text, count=1, flags=re.S)
else:
    text = re.sub(r'<global>',
                  '<global>\\n    <jsonout_output>yes</jsonout_output>',
                  text, count=1)
text = re.sub(
    r'\\s*<!-- e2e-alerts-json-syslog -->\\s*<syslog_output>.*?</syslog_output>',
    '', text, flags=re.S)
text = re.sub(
    r'\\s*<!-- e2e-alerts-json-inject -->\\s*<localfile>.*?</localfile>',
    '', text, flags=re.S)
block = '''  <!-- e2e-alerts-json-inject -->
  <localfile>
    <log_format>syslog</log_format>
    <location>$inject_log</location>
  </localfile>
  <!-- e2e-alerts-json-syslog -->
  <syslog_output>
    <server>127.0.0.1</server>
    <port>$JSON_PORT</port>
    <format>json</format>
  </syslog_output>
'''
if '</ossec_config>' not in text:
    raise SystemExit('ossec.conf missing </ossec_config>')
text = re.sub(r'</ossec_config>', block + '</ossec_config>', text, count=1)
p.write_text(text)
PY
            plist=$OSSEC_DIR/bin/.process_list
            touch \$plist
            if ! grep -q '^CSYSLOG_DAEMON=ossec-csyslogd' \$plist; then
                echo 'CSYSLOG_DAEMON=ossec-csyslogd' >> \$plist
            fi
            $OSSEC_DIR/bin/ossec-control enable client-syslog >/dev/null 2>&1 || true
            pkill -x ossec-csyslogd >/dev/null 2>&1 || true
            echo E2E_JSON_SYSLOG_MARK \$(date -Iseconds) >> $OSSEC_DIR/logs/ossec.log
            $OSSEC_DIR/bin/ossec-control restart
            sleep 3
            pgrep -x ossec-analysisd >/dev/null
            pgrep -x ossec-csyslogd >/dev/null
            grep -F '127.0.0.1:$JSON_PORT' $OSSEC_DIR/logs/ossec.log >/dev/null
        "
        log "OK: jsonout_output + JSON syslog_output on 127.0.0.1:${JSON_PORT}; analysisd+csyslogd running"

        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "
                mark=\$(grep -n 'E2E_JSON_SYSLOG_MARK' $OSSEC_DIR/logs/ossec.log | tail -1 | cut -d: -f1)
                [[ -n \"\$mark\" ]] || exit 1
                tail -n +\$mark $OSSEC_DIR/logs/ossec.log | grep -F $(printf '%q' "$inject_log") | grep -q Analyzing
            "; then
                _ok=1
                break
            fi
            _now=$(date +%s)
            if (( _now - _start >= 30 )); then
                break
            fi
            sleep 1
        done
        [[ "$_ok" -eq 1 ]] || die "logcollector did not start analyzing $inject_log"

        transport_bash "
            set -e
            ts=\$(date '+%b %e %H:%M:%S')
            host=\$(hostname -s)
            line=\"\$ts \$host sshd[\$\$]: Failed password for invalid user $token from 203.0.113.10 port 5555 ssh2\"
            echo \"\$line\" >> $inject_log
            echo \"\$line\"
        "
        log "injected unique sshd failure token=$token into $inject_log"

        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "
                grep -F $(printf '%q' "$token") $OSSEC_DIR/logs/alerts/alerts.json 2>/dev/null | grep -F '\"agent_name\"' >/dev/null
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
        if [[ "$_ok" -ne 1 ]]; then
            show_remote_outputs "$token"
            transport_bash "tail -40 $OSSEC_DIR/logs/ossec.log || true" || true
            die "alerts.json did not contain token $token with agent_name"
        fi
        log "OK: alerts.json contains token and agent_name"

        _start=$(date +%s)
        _ok=0
        while true; do
            if transport_bash "
                grep -F $(printf '%q' "$token") $capture 2>/dev/null | grep -F '\"agent_name\"' >/dev/null
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
        show_remote_outputs "$token"
        if [[ "$_ok" -ne 1 ]]; then
            transport_bash "tail -40 $OSSEC_DIR/logs/ossec.log || true" || true
            die "JSON syslog capture did not contain token $token with agent_name"
        fi
        log "OK: JSON syslog datagram contains token and agent_name"

        stop_json_listener
        trap - EXIT

        log "OK: alerts.json JSON syslog on $name"
    ); then
        failed=1
        [[ "$KEEP_GOING" == "1" ]] || die "05-alerts-json-syslog failed on $name"
        warn "continuing after failure on $name"
    fi
done < <(inventory_list_hosts "$INVENTORY" "$BACKEND_FILTER" server)

[[ "$failed" -eq 0 ]] || die "05-alerts-json-syslog had failures"
log "05-alerts-json-syslog: all server hosts OK"
