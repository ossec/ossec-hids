#!/usr/bin/env bash
# Post-server-build: jsonout_output defaults on when <jsonout_output> is omitted.
set -euo pipefail

SRC_DIR="${1:-.}"
cd "$SRC_DIR"

fail() { echo "VERIFY FAIL: $*" >&2; exit 1; }
ok() { echo "VERIFY OK: $*"; }

[[ -f analysisd/config.c ]] || fail "analysisd/config.c missing"
[[ -f config.a ]] || fail "config.a missing (build TARGET=server first)"
[[ -f shared.a ]] || fail "shared.a missing"

make -f tests/regressions/Makefile jsonout_default
./jsonout_default || fail "jsonout_default failed"
ok "jsonout_output defaults on when undeclared"
