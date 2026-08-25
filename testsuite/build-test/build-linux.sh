#!/bin/sh
# Invoked inside the build container (cwd = repo src/). Keep POSIX sh for /bin/sh.
set -eu

MAKE_TARGET="${MAKE_TARGET:-server}"
MAKE_OPTS="${MAKE_OPTS:-USE_AUDIT=yes USE_CURL=yes USE_MAGIC=no}"

echo "== make clean =="
make clean

echo "== make TARGET=${MAKE_TARGET} ${MAKE_OPTS} =="
# shellcheck disable=SC2086
make TARGET="${MAKE_TARGET}" ${MAKE_OPTS} -j"$(nproc 2>/dev/null || echo 2)"

if [ "${TEST:-}" = "1" ]; then
    if [ "${MAKE_TARGET}" = "agent" ]; then
        echo "== verify syscheck audit =="
        chmod +x ../testsuite/build-test/verify-syscheck-audit.sh
        ../testsuite/build-test/verify-syscheck-audit.sh .
    elif [ "${MAKE_TARGET}" = "server" ] || [ "${MAKE_TARGET}" = "hybrid" ]; then
        echo "== verify alerts.json / JSON syslog =="
        chmod +x ../testsuite/build-test/verify-alerts-json.sh
        ../testsuite/build-test/verify-alerts-json.sh .
    else
        echo "== skip post-build verify for MAKE_TARGET=${MAKE_TARGET} =="
    fi
else
    echo "== skip post-build verify (set TEST=1 to enable) =="
fi
