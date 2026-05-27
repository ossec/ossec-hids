#!/bin/sh
# SIGHUP reload regression checks (PR #2207 + security remediation).
# Usage: ./contrib/test-reload.sh [OSSEC_DIR]
# Optional: TEST_RELOAD_STRESS=1 for 50x reload RSS check
# Optional: TEST_RELOAD_LEAK=1 to compare analysisd RSS before/after 10 failed reloads
# Optional: TEST_RELOAD_VERIFY_RULES=1 for environments with a full ruleset + logger
# Optional: TEST_RELOAD_AGENT=1 when ossec-agentd is running (client installs)

DIR="${1:-${OSSEC_DIR:-/var/ossec}}"
CTL="${DIR}/bin/ossec-control"
LOG="${DIR}/logs/ossec.log"
CONF="${DIR}/etc/ossec.conf"
FAIL=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAIL=1; }
skip() { echo "SKIP: $1"; }

if [ ! -x "$CTL" ]; then
    echo "SKIP: $CTL not found"
    exit 0
fi

echo "=== Reload smoke test (OSSEC_DIR=$DIR) ==="

PIDS_BEFORE=""
for d in ossec-analysisd ossec-logcollector ossec-remoted ossec-syscheckd ossec-monitord; do
    pid=$(cat "${DIR}/var/run/${d}"*.pid 2>/dev/null | head -1)
    PIDS_BEFORE="${PIDS_BEFORE}${d}=${pid} "
done
echo "Before: $PIDS_BEFORE"

OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
sleep 2

STABLE=1
for d in ossec-analysisd ossec-logcollector ossec-remoted ossec-syscheckd ossec-monitord; do
    before=$(echo "$PIDS_BEFORE" | sed -n "s/.*${d}=\([^ ]*\).*/\1/p")
    after=$(cat "${DIR}/var/run/${d}"*.pid 2>/dev/null | head -1)
    if [ -n "$before" ] && [ "$before" != "$after" ]; then
        fail "$d PID changed ($before -> $after)"
        STABLE=0
    fi
done
[ "$STABLE" = "1" ] && pass "PIDs stable after reload"

if grep -qi "SIGHUP received" "$LOG" 2>/dev/null; then
    pass "SIGHUP logged"
else
    fail "no SIGHUP lines in $LOG"
fi

if grep -qi "not yet fully implemented" "$LOG" 2>/dev/null; then
    fail "placeholder reload messages still present"
else
    pass "no placeholder reload messages"
fi

RUNNING=1
for d in ossec-analysisd ossec-logcollector ossec-remoted ossec-syscheckd ossec-monitord ossec-execd; do
    if "$CTL" status 2>/dev/null | grep -q "${d} not running"; then
        fail "${d} not running after reload"
        RUNNING=0
    fi
done
[ "$RUNNING" = "1" ] && pass "core daemons running after reload"

# ar.conf must retain command lines after successful reload (AR-1)
echo "=== ar.conf preserved after reload ==="
ARCONF="${DIR}/etc/shared/ar.conf"
if [ ! -f "$ARCONF" ]; then
    skip "no $ARCONF"
else
    AR_LINES_BEFORE=$(wc -l < "$ARCONF" 2>/dev/null | tr -d ' ')
    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 2
    AR_LINES_AFTER=$(wc -l < "$ARCONF" 2>/dev/null | tr -d ' ')
    if [ -n "$AR_LINES_BEFORE" ] && [ -n "$AR_LINES_AFTER" ] && [ "$AR_LINES_BEFORE" = "$AR_LINES_AFTER" ]; then
        pass "ar.conf line count unchanged after reload ($AR_LINES_AFTER lines)"
    elif [ -n "$AR_LINES_AFTER" ] && [ "$AR_LINES_AFTER" -gt 2 ]; then
        pass "ar.conf has AR commands after reload ($AR_LINES_AFTER lines)"
    else
        fail "ar.conf truncated or empty after reload (before=$AR_LINES_BEFORE after=$AR_LINES_AFTER)"
    fi
fi

# Failed reload must not stop analysisd or discard live rules (atomic staging)
echo "=== Bad config reload (analysisd must stay up, keep rules) ==="
if [ ! -f "$CONF" ]; then
    skip "no $CONF for bad-reload test"
else
    RULES_DIR="${DIR}/rules"
    mkdir -p "$RULES_DIR" 2>/dev/null || true
    GOOD_RULE="${RULES_DIR}/local_reload_test_good.xml"
    BAD_RULE="${RULES_DIR}/local_reload_test_bad.xml"
    GOOD_INCLUDE="local_reload_test_good.xml"
    BAD_INCLUDE="local_reload_test_bad.xml"
    CONF_BAK="${CONF}.test-reload.bak"
    cp "$CONF" "$CONF_BAK"

    cat > "$GOOD_RULE" <<'EOF'
<group name="reload_test_good,">
  <rule id="1999998" level="5">
    <description>reload test good marker</description>
  </rule>
</group>
EOF

    cat > "$BAD_RULE" <<'EOF'
<group name="reload_test_bad,">
  <rule id="1999999" level="5">
    <description>reload test bad unclosed
EOF

    add_include() {
        inc="$1"
        if ! grep -q "$inc" "$CONF" 2>/dev/null; then
            sed -i "/<rules>/a\\    <include>${inc}</include>" "$CONF" 2>/dev/null ||
                sed -i "/<rule /i\\    <include>${inc}</include>" "$CONF" 2>/dev/null ||
                echo "    <include>${inc}</include>" >> "$CONF"
        fi
    }
    add_include "$GOOD_INCLUDE"
    add_include "$BAD_INCLUDE"

    APID=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)

    # Load good rule first
    sleep 6
    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 2

    if [ "${TEST_RELOAD_VERIFY_RULES:-0}" = "1" ] && [ -x "${DIR}/bin/logger" ]; then
        "${DIR}/bin/logger" "reload_test_good marker event"
        sleep 2
        if grep -q "1999998" "$LOG" 2>/dev/null; then
            pass "good rule fired before bad reload"
        else
            skip "good rule 1999998 not seen (ruleset/logger may differ)"
        fi
    fi

    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 2
    APID2=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)

    if [ -n "$APID" ] && [ "$APID" = "$APID2" ] && ps -p "$APID2" >/dev/null 2>&1; then
        pass "analysisd survived bad-rules reload"
    else
        fail "analysisd died or restarted on bad-rules reload"
    fi

    if grep -qi "using previous configuration\|Error reloading configuration" "$LOG" 2>/dev/null; then
        pass "failed reload logged (staging abort)"
    else
        fail "no failed-reload message in log"
    fi

    if grep -qi "partial reload applied\|Partial configuration reload" "$LOG" 2>/dev/null; then
        fail "unexpected partial-reload message after staging-only failure"
    else
        pass "no partial-reload message after staging failure"
    fi

    if tail -200 "$LOG" 2>/dev/null | grep -qi "Rules in an inconsistent state"; then
        fail "inconsistent rules state after failed reload (recent log)"
    else
        pass "no inconsistent-rules log after failed reload"
    fi

    mv -f "$CONF_BAK" "$CONF"
    rm -f "$BAD_RULE"
    sleep 6
    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 2

    if [ "${TEST_RELOAD_VERIFY_RULES:-0}" = "1" ] && [ -x "${DIR}/bin/logger" ]; then
        "${DIR}/bin/logger" "reload_test_good marker after recovery"
        sleep 2
        if grep -q "1999998" "$LOG" 2>/dev/null; then
            pass "rules still active after failed reload and recovery"
        else
            fail "rule 1999998 not firing after recovery reload"
        fi
    fi

    rm -f "$GOOD_RULE"
    sleep 6
    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 1
fi

# Bad local_decoder.xml must abort staging without killing analysisd (DEC-1)
echo "=== Bad decoder reload (analysisd must stay up) ==="
LOCAL_DEC="${DIR}/etc/local_decoder.xml"
if [ ! -f "${DIR}/etc/decoder.xml" ]; then
    skip "no ${DIR}/etc/decoder.xml"
else
    APID=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)
    if [ -f "$LOCAL_DEC" ]; then
        LOCAL_DEC_BAK="${LOCAL_DEC}.test-reload.bak"
        cp "$LOCAL_DEC" "$LOCAL_DEC_BAK"
    else
        LOCAL_DEC_BAK=""
        : > "$LOCAL_DEC"
    fi

    cat > "$LOCAL_DEC" <<'EOF'
<decoder name="reload_test_bad_decoder">
  <prematch>reload_test_bad_decoder
EOF

    sleep 6
    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 2
    APID2=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)

    if [ -n "$APID" ] && [ "$APID" = "$APID2" ] && ps -p "$APID2" >/dev/null 2>&1; then
        pass "analysisd survived bad-decoder reload"
    else
        fail "analysisd died or restarted on bad-decoder reload"
    fi

    if tail -200 "$LOG" 2>/dev/null | grep -qi "using previous configuration\|Error reloading configuration"; then
        pass "bad-decoder reload logged staging abort"
    else
        fail "no failed-reload message after bad decoder"
    fi

    if tail -200 "$LOG" 2>/dev/null | grep -qi "partial reload applied\|Partial configuration reload"; then
        fail "unexpected partial-reload after bad-decoder staging failure"
    else
        pass "no partial-reload after bad-decoder failure"
    fi

    if [ -n "$LOCAL_DEC_BAK" ]; then
        mv -f "$LOCAL_DEC_BAK" "$LOCAL_DEC"
    else
        rm -f "$LOCAL_DEC"
    fi
    sleep 6
    OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
    sleep 1
fi

if [ "${TEST_RELOAD_LEAK:-0}" = "1" ]; then
    echo "=== Leak check: 10 failed reloads (RSS) ==="
    APID=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)
    if [ -n "$APID" ] && [ -r "/proc/${APID}/status" ]; then
        RSS_BEFORE=$(awk '/VmRSS:/ {print $2}' "/proc/${APID}/status")
        RULES_DIR="${DIR}/rules"
        LEAK_BAD="${RULES_DIR}/local_reload_leak_bad.xml"
        mkdir -p "$RULES_DIR" 2>/dev/null || true
        CONF_BAK="${CONF}.test-reload-leak.bak"
        cp "$CONF" "$CONF_BAK"
        cat > "$LEAK_BAD" <<'EOF'
<group name="reload_leak_bad,">
  <rule id="1999997" level="5">
    <description>broken
EOF
        if ! grep -q "local_reload_leak_bad.xml" "$CONF" 2>/dev/null; then
            sed -i "/<rules>/a\\    <include>local_reload_leak_bad.xml</include>" "$CONF" 2>/dev/null ||
                echo "    <include>local_reload_leak_bad.xml</include>" >> "$CONF"
        fi
        i=0
        while [ "$i" -lt 10 ]; do
            OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload >/dev/null 2>&1
            sleep 1
            i=$((i + 1))
        done
        RSS_AFTER=$(awk '/VmRSS:/ {print $2}' "/proc/${APID}/status")
        mv -f "$CONF_BAK" "$CONF"
        rm -f "$LEAK_BAD"
        OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload >/dev/null 2>&1
        # Allow 32 MiB growth (staging trees freed on abort)
        if [ "$RSS_AFTER" -le $((RSS_BEFORE + 32768)) ]; then
            pass "RSS within 32MiB after 10 failed reloads (${RSS_BEFORE} -> ${RSS_AFTER} kB)"
        else
            fail "RSS grew more than 32MiB after failed reloads (${RSS_BEFORE} -> ${RSS_AFTER} kB)"
        fi
    else
        skip "cannot read analysisd RSS from /proc"
    fi
fi

if [ "${TEST_RELOAD_AGENT:-0}" = "1" ]; then
    echo "=== Agent reload (optional) ==="
    AGPID=$(cat "${DIR}/var/run/ossec-agentd"*.pid 2>/dev/null | head -1)
    if [ -z "$AGPID" ]; then
        skip "ossec-agentd not running"
    else
        OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload
        sleep 2
        AGPID2=$(cat "${DIR}/var/run/ossec-agentd"*.pid 2>/dev/null | head -1)
        if [ "$AGPID" = "$AGPID2" ] && ps -p "$AGPID2" >/dev/null 2>&1; then
            pass "agentd stable after reload (pid $AGPID2)"
        else
            fail "agentd died or restarted on reload"
        fi
    fi
fi

if [ "${TEST_RELOAD_STRESS:-0}" = "1" ]; then
    echo "=== Stress: 50 reloads ==="
    APID=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)
    i=0
    while [ "$i" -lt 50 ]; do
        OSSEC_RELOAD_MIN_INTERVAL=0 "$CTL" reload >/dev/null 2>&1
        sleep 1
        i=$((i + 1))
    done
    APID2=$(cat "${DIR}/var/run/ossec-analysisd"*.pid 2>/dev/null | head -1)
    if [ -n "$APID" ] && [ "$APID" = "$APID2" ] && ps -p "$APID2" >/dev/null 2>&1; then
        pass "analysisd stable after 50 reloads"
    else
        fail "analysisd not stable after stress reloads"
    fi
    if grep -qi "Maximum configuration reload count" "$LOG" 2>/dev/null; then
        pass "reload cap may have triggered (expected after 10 default)"
    fi
fi

exit "$FAIL"
