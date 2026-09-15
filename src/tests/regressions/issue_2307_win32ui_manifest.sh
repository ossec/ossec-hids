#!/bin/bash
# Regression test for Issue #2307 - win32ui.exe SideBySide assemblyIdentity version
# https://github.com/ossec/ossec-hids/issues/2307
#
# Windows SxS requires assemblyIdentity version as four unsigned parts
# (major.minor.build.revision), each 0-65535. "1.5" is invalid and prevents
# win32ui.exe from starting (Event ID 63).

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSSEC_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
MANIFEST="${OSSEC_ROOT}/src/win32/ui/os_win32ui.exe.manifest"
EXE="${OSSEC_WIN32UI:-${OSSEC_ROOT}/src/win32/os_win32ui.exe}"
RESOURCE_O="${OSSEC_ROOT}/src/win32/resource.o"

failures=0

# Microsoft fourPartVersionType: four decimal parts, each 0-65535.
is_four_part_version() {
    local ver="$1"
    local IFS=.
    local -a parts
    # shellcheck disable=SC2206
    parts=($ver)
    if [ "${#parts[@]}" -ne 4 ]; then
        return 1
    fi
    local p
    for p in "${parts[@]}"; do
        case "$p" in
            ''|*[!0-9]*) return 1 ;;
        esac
        if [ "$p" -gt 65535 ]; then
            return 1
        fi
    done
    return 0
}

check_identity_blob() {
    local label="$1"
    local blob="$2"
    local ver

    if [ -z "$blob" ]; then
        echo "FAIL: ${label}: no assemblyIdentity found"
        failures=$((failures + 1))
        return
    fi

    if ! printf '%s' "$blob" | grep -q 'name="os_win32ui.exe"'; then
        echo "FAIL: ${label}: assemblyIdentity name is not os_win32ui.exe"
        echo "      ${blob}"
        failures=$((failures + 1))
    fi

    ver=$(printf '%s' "$blob" | sed -n 's/.*version="\([^"]*\)".*/\1/p' | head -1)
    if [ -z "$ver" ]; then
        echo "FAIL: ${label}: version attribute missing"
        failures=$((failures + 1))
        return
    fi

    if [ "$ver" = "1.5" ]; then
        echo "FAIL: ${label}: version=\"1.5\" is the invalid two-part value from #2307"
        failures=$((failures + 1))
        return
    fi

    if ! is_four_part_version "$ver"; then
        echo "FAIL: ${label}: version=\"${ver}\" is not major.minor.build.revision (0-65535 each)"
        failures=$((failures + 1))
        return
    fi

    echo "OK: ${label}: version=${ver}"
}

extract_identity() {
    # Prefer UTF-8 XML; fall back to UTF-16LE used by some resource compilers.
    python3 - "$1" <<'PY'
import re, sys

data = open(sys.argv[1], "rb").read()
texts = [data.decode("utf-8", "ignore"), data.decode("utf-16le", "ignore")]
pat = re.compile(r"<assemblyIdentity\b[^>]*?/?>", re.IGNORECASE | re.DOTALL)
for text in texts:
    matches = [m.group(0) for m in pat.finditer(text) if "os_win32ui.exe" in m.group(0)]
    if not matches:
        matches = [m.group(0) for m in pat.finditer(text)]
    if matches:
        # Collapse whitespace so later grep/sed is stable.
        blob = re.sub(r"\s+", " ", matches[0]).strip()
        sys.stdout.write(blob)
        sys.exit(0)
sys.exit(1)
PY
}

echo "Regression Test: Issue #2307 - win32ui assemblyIdentity version"
echo "==============================================================="

if [ ! -f "$MANIFEST" ]; then
    echo "FAIL: source manifest missing: $MANIFEST"
    exit 1
fi

src_blob=$(extract_identity "$MANIFEST" || true)
check_identity_blob "source manifest" "$src_blob"

if [ -f "$RESOURCE_O" ]; then
    res_blob=$(extract_identity "$RESOURCE_O" || true)
    check_identity_blob "win32/resource.o" "$res_blob"
else
    echo "SKIP: win32/resource.o not built"
fi

if [ -f "$EXE" ]; then
    exe_blob=$(extract_identity "$EXE" || true)
    check_identity_blob "os_win32ui.exe" "$exe_blob"

    # Direct string scan for the historic invalid value (ASCII and UTF-16LE).
    if python3 - "$EXE" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
needles = [b'version="1.5"', 'version="1.5"'.encode("utf-16le")]
sys.exit(0 if any(n in data for n in needles) else 1)
PY
    then
        echo "FAIL: ${EXE} still contains version=\"1.5\""
        failures=$((failures + 1))
    else
        echo "OK: os_win32ui.exe does not contain version=\"1.5\""
    fi
else
    echo "SKIP: os_win32ui.exe not built (set OSSEC_WIN32UI to test a binary)"
fi

if [ "$failures" -ne 0 ]; then
    echo
    echo "FAIL: ${failures} check(s) failed"
    exit 1
fi

echo
echo "PASS: win32ui assemblyIdentity version is SideBySide-valid"
exit 0
