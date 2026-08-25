#!/usr/bin/env bash
# Syscheck E2E helpers (controller-side; use with HOST_* + transport_*).

SK_TREE="${SK_TREE:-/opt/e2e-syscheck}"
SK_DB="${OSSEC_DIR}/queue/syscheck/syscheck"
SK_ALERTS="${OSSEC_DIR}/logs/alerts/alerts.log"
SK_LOG="${OSSEC_DIR}/logs/ossec.log"

# Write a unique mark into ossec.log so later greps are scoped to this run.
sk_stamp_mark() {
    local tag="${1:-E2E_SYSCHECK_MARK}"
    SK_MARK_TAG="$tag"
    transport_bash "echo \"${tag} \$(date -Iseconds)\" >> $SK_LOG"
}

sk_mark_line() {
    transport_bash "grep -n '${SK_MARK_TAG:-E2E_SYSCHECK_MARK}' $SK_LOG | tail -1 | cut -d: -f1"
}

# Run remote grep only on log lines after the last mark.
sk_log_since_mark() {
    local pattern="$1"
    transport_bash "
        mark=\$(grep -n '${SK_MARK_TAG:-E2E_SYSCHECK_MARK}' $SK_LOG | tail -1 | cut -d: -f1)
        [[ -n \"\$mark\" ]] || exit 1
        tail -n +\$mark $SK_LOG | grep -E $(printf '%q' "$pattern")
    "
}

sk_alert_since_mark() {
    local pattern="$1"
    # alerts.log has no mark; use timestamp window + path patterns from caller.
    transport_bash "grep -E $(printf '%q' "$pattern") $SK_ALERTS 2>/dev/null | tail -20"
}

# Replace all <syscheck> blocks with $1 XML fragment; disable rootcheck to cut queue noise.
# Optional extra global bits (alert_new_files etc.) go inside the syscheck fragment.
sk_apply_syscheck_xml() {
    local xml_fragment="$1"
    local tmp
    tmp=$(mktemp)
    printf '%s\n' "$xml_fragment" >"$tmp"
    transport_copy "$tmp" "$E2E_REMOTE_TMP/sk-fragment.xml"
    rm -f "$tmp"

    transport_bash "
        set -e
        conf=$OSSEC_DIR/etc/ossec.conf
        cp -a \$conf \$conf.bak.sk-e2e
        python3 - <<'PY'
from pathlib import Path
import re
p = Path('$OSSEC_DIR/etc/ossec.conf')
text = p.read_text()
frag = Path('$E2E_REMOTE_TMP/sk-fragment.xml').read_text().rstrip() + '\n'
text2 = re.sub(r'[ \t]*<syscheck>.*?</syscheck>\s*', '', text, flags=re.S)
# Disable rootcheck to avoid competing with syscheck on the MQ during tests
text2 = re.sub(
    r'[ \t]*<rootcheck>.*?</rootcheck>\s*',
    '  <rootcheck>\n    <disabled>yes</disabled>\n  </rootcheck>\n',
    text2,
    count=1,
    flags=re.S,
)
if '<rootcheck>' not in text2:
    text2 = re.sub(r'</ossec_config>', '  <rootcheck>\n    <disabled>yes</disabled>\n  </rootcheck>\n</ossec_config>', text2, count=1)
text2 = re.sub(r'</ossec_config>', frag + '</ossec_config>', text2, count=1)
p.write_text(text2)
PY
    "
}

# Minimal realtime tree: one directory, low frequency, optional extras in fragment.
sk_isolate_tree() {
    local tree="${1:-$SK_TREE}"
    local extra_dirs="${2:-}"
    local extras="${3:-}"
    SK_TREE="$tree"
    transport_bash "
        set -e
        rm -rf $(printf '%q' "$tree")
        mkdir -p $(printf '%q' "$tree")
        echo 'baseline-content' > $(printf '%q' "$tree")/watched.txt
        rm -f $OSSEC_DIR/queue/syscheck/syscheck $OSSEC_DIR/queue/syscheck/.syscheck.cpt
        mkdir -p $OSSEC_DIR/queue/syscheck
        chown -R ossec:ossec $OSSEC_DIR/queue/syscheck 2>/dev/null || true
    "
    local fragment
    fragment=$(cat <<EOF
  <syscheck>
    <frequency>30</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes">${tree}</directories>
${extra_dirs}${extras}  </syscheck>
EOF
)
    sk_apply_syscheck_xml "$fragment"
    pkg_restart_ossec
    # Stamp after start so stop-time analysisd join timeouts are out of scope.
    sk_stamp_mark "E2E_SYSCHECK_MARK"
    sk_wait_analysisd_stable
    sleep 1
}

sk_wait_prescan() {
    local path="${1:-$SK_TREE/watched.txt}"
    local start now
    start=$(date +%s)
    while true; do
        if transport_bash "
            mark=\$(grep -n '${SK_MARK_TAG:-E2E_SYSCHECK_MARK}' $SK_LOG | tail -1 | cut -d: -f1)
            [[ -n \"\$mark\" ]] || exit 1
            tail -n +\$mark $SK_LOG | grep -F 'Finished creating syscheck database' >/dev/null
            [[ -f $SK_DB ]]
            grep -aF $(printf '%q' "$path") $SK_DB >/dev/null 2>&1
        "; then
            log "OK: syscheck pre-scan indexed $path"
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= E2E_TIMEOUT )); then
            die "timeout waiting for syscheck pre-scan to index $path"
        fi
        sleep 2
    done
}

sk_wait_ending_scan() {
    local min_count="${1:-1}"
    local start now
    start=$(date +%s)
    while true; do
        if transport_bash "
            mark=\$(grep -n '${SK_MARK_TAG:-E2E_SYSCHECK_MARK}' $SK_LOG | tail -1 | cut -d: -f1)
            c=\$(tail -n +\$mark $SK_LOG | grep -cF 'Ending syscheck scan' || true)
            [[ \"\$c\" -ge $min_count ]]
        "; then
            log "OK: Ending syscheck scan seen (>= $min_count)"
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= E2E_TIMEOUT )); then
            die "timeout waiting for Ending syscheck scan (need >= $min_count)"
        fi
        sleep 2
    done
}

sk_wait_analysisd_stable() {
    # Require analysisd + queue for a short dwell. Do not treat stop-time
    # "timed out joining" lines as failure — those often appear after mark
    # when we stamp before restart.
    local start now pid1 pid2
    start=$(date +%s)
    while true; do
        if transport_bash "
            pgrep -x ossec-analysisd >/dev/null
            [[ -S $OSSEC_DIR/queue/ossec/queue ]]
        "; then
            pid1=$(transport_bash "pgrep -x ossec-analysisd | head -1")
            sleep 5
            pid2=$(transport_bash "pgrep -x ossec-analysisd | head -1" || true)
            if [[ -n "$pid1" && "$pid1" == "$pid2" ]] && \
               transport_bash "[[ -S $OSSEC_DIR/queue/ossec/queue ]]"; then
                log "OK: analysisd stable with queue socket (pid $pid1)"
                return 0
            fi
        fi
        now=$(date +%s)
        if (( now - start >= 90 )); then
            die "analysisd not stable (missing process or queue)"
        fi
        sleep 2
    done
}

sk_assert_no_socketerr_since_mark() {
    transport_bash "grep -q '${SK_MARK_TAG:-E2E_SYSCHECK_MARK}' $SK_LOG" \
        || die "queue health gate: run mark not found in $SK_LOG"
    if transport_bash "
        mark=\$(grep -n '${SK_MARK_TAG:-E2E_SYSCHECK_MARK}' $SK_LOG | tail -1 | cut -d: -f1)
        [[ -n \"\$mark\" ]] || exit 1
        tail -n +\$mark $SK_LOG | grep -E 'socketerr \\(not available\\)|Error sending message to queue' >/dev/null
    "; then
        die "queue health gate failed: socketerr / send errors since mark"
    fi
    log "OK: no socketerr since mark"
}

sk_assert_db_has() {
    local path="$1"
    transport_bash "grep -aF $(printf '%q' "$path") $SK_DB >/dev/null" \
        || die "syscheck DB missing path: $path"
    log "OK: DB has $path"
}

sk_assert_db_lacks() {
    local path="$1"
    if transport_bash "[[ -f $SK_DB ]] && grep -aF $(printf '%q' "$path") $SK_DB >/dev/null"; then
        die "syscheck DB unexpectedly contains: $path"
    fi
    log "OK: DB lacks $path"
}

# Wait for an alert matching pattern (typically Rule: 550 / path / description).
sk_wait_alert() {
    local pattern="$1"
    local desc="${2:-alert matching $pattern}"
    local start now
    start=$(date +%s)
    while true; do
        if transport_bash "grep -E $(printf '%q' "$pattern") $SK_ALERTS >/dev/null 2>&1"; then
            # Prefer alerts after our mark time when possible: also require path if provided via pattern
            log "OK: $desc"
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= E2E_TIMEOUT )); then
            die "timeout waiting for $desc"
        fi
        sleep 2
    done
}

# Clear recent matching noise by truncating alerts log (dedicated E2E host only).
sk_truncate_alerts() {
    transport_bash "
        : > $SK_ALERTS
        chown ossec:ossec $SK_ALERTS 2>/dev/null || true
    "
}

# Queue health gate: isolated tree, first scan clean, content change → rule 550.
sk_queue_gate() {
    local tree="${1:-$SK_TREE}"
    log "=== syscheck queue health gate on $HOST_NAME ==="
    sk_isolate_tree "$tree"
    sk_wait_prescan "$tree/watched.txt"
    sk_wait_ending_scan 1
    sk_assert_no_socketerr_since_mark
    sk_truncate_alerts

    transport_bash "echo changed-\$(date +%s)-queue-gate > $(printf '%q' "$tree")/watched.txt"

    _start=$(date +%s)
    _ok=0
    while true; do
        if transport_bash "grep -E 'Rule: 550' -A8 $SK_ALERTS | grep -F $(printf '%q' "$tree/watched.txt") >/dev/null"; then
            _ok=1
            break
        fi
        _now=$(date +%s)
        if (( _now - _start >= E2E_TIMEOUT )); then
            break
        fi
        sleep 2
    done
    [[ "$_ok" -eq 1 ]] || die "rule 550 integrity alert for $tree/watched.txt not observed"
    sk_assert_no_socketerr_since_mark
    log "OK: queue health gate passed (rule 550 observed)"
}
