#!/usr/bin/env bash
# Remote assertions via transport_bash / transport_exec.

assert_cmd() {
    local desc="$1"
    shift
    if transport_exec "$@"; then
        log "OK: $desc"
    else
        die "FAIL: $desc"
    fi
}

assert_process() {
    local name="$1"
    local start now
    start=$(date +%s)
    while true; do
        if transport_exec pgrep -x "$name" >/dev/null 2>&1; then
            log "OK: process $name running"
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= E2E_TIMEOUT )); then
            die "timeout after ${E2E_TIMEOUT}s waiting for process $name on $HOST_NAME"
        fi
        sleep 2
    done
}

assert_no_fatal_startup() {
    transport_bash "
        set -e
        logf=$OSSEC_DIR/logs/ossec.log
        [[ -f \$logf ]] || exit 0
        if grep -E 'FATAL|CRITICAL' \$logf | grep -viE 'already running|Duplicate' >/dev/null; then
            echo 'FATAL/CRITICAL lines in ossec.log:' >&2
            grep -E 'FATAL|CRITICAL' \$logf | tail -20 >&2
            exit 1
        fi
    "
    log "OK: no FATAL/CRITICAL in ossec.log"
}

assert_server_daemons() {
    assert_process ossec-analysisd
    assert_process ossec-remoted
    assert_process ossec-syscheckd
    assert_no_fatal_startup
}

assert_agent_daemon() {
    assert_process ossec-agentd
    assert_no_fatal_startup
}

assert_remote_grep() {
    local desc="$1" pattern="$2" path="$3"
    local start now
    start=$(date +%s)
    while true; do
        if transport_bash "grep -Eq $(printf '%q' "$pattern") $(printf '%q' "$path")"; then
            log "OK: $desc"
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= E2E_TIMEOUT )); then
            die "timeout after ${E2E_TIMEOUT}s waiting for: $desc"
        fi
        sleep 2
    done
}

assert_logtest_ok() {
    local fixture_remote="$1"
    transport_bash "
        set -e
        out=\$($OSSEC_DIR/bin/ossec-logtest -q < $(printf '%q' "$fixture_remote") 2>&1 || true)
        echo \"\$out\" | tee $E2E_REMOTE_TMP/logtest.out >/dev/null
        echo \"\$out\" | grep -Eqi 'alert|Phase 3|Rule id'
    "
    log "OK: ossec-logtest produced rule/alert output"
}
