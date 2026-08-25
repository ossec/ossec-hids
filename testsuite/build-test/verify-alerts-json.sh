#!/usr/bin/env bash
# Post-server-build checks for alerts.json / JSON syslog_output (cwd=src).
set -euo pipefail

SRC_DIR="${1:-.}"
cd "$SRC_DIR"

fail() { echo "VERIFY FAIL: $*" >&2; exit 1; }
ok() { echo "VERIFY OK: $*"; }

[[ -x ossec-analysisd ]] || fail "ossec-analysisd binary missing"
[[ -x ossec-csyslogd ]] || fail "ossec-csyslogd binary missing"
[[ -f os_csyslogd/json-queue.o ]] || fail "os_csyslogd/json-queue.o missing"
[[ -f libcJSON.a ]] || fail "libcJSON.a missing"

# Function/symbol names may be stripped; log text is a stable string literal.
if ! strings ossec-csyslogd | grep -q 'JSON file queue connected'; then
    if ! strings ossec-csyslogd | grep -q 'OS_Alert_SendSyslog_JSON' &&
       ! strings ossec-csyslogd | grep -q 'jqueue_next'; then
        fail "ossec-csyslogd missing JSON alerts.json queue"
    fi
fi
ok "csyslogd JSON syslog / alerts.json path present"

TEST_SRC="../testsuite/build-test/alerts-json/test_jqueue.c"
TEST_BIN="../testsuite/build-test/alerts-json/test_jqueue"
[[ -f "$TEST_SRC" ]] || fail "missing $TEST_SRC"

CC="${CC:-cc}"
${CC} -I./ -I./headers -I./external/cJSON -DARGV0=\"test_jqueue\" \
    -o "$TEST_BIN" "$TEST_SRC" os_csyslogd/json-queue.o \
    shared.a os_xml.a os_net.a os_regex.a libcJSON.a \
    -lm -lpthread -lpcre2-8

"$TEST_BIN" || fail "test_jqueue failed"
ok "jqueue test passed"

rm -f "$TEST_BIN"
ok "alerts.json / JSON syslog verification complete"
