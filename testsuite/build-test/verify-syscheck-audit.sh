#!/usr/bin/env bash
# Post-build checks for FIM audit / optional eBPF (run inside container with cwd=src).
set -euo pipefail

SRC_DIR="${1:-.}"
cd "$SRC_DIR"

fail() { echo "VERIFY FAIL: $*" >&2; exit 1; }
ok() { echo "VERIFY OK: $*"; }

[[ -x ossec-syscheckd ]] || fail "ossec-syscheckd binary missing"

if ! strings ossec-syscheckd | grep -q 'audit_init'; then
    fail "ossec-syscheckd does not reference audit_init (ENABLE_AUDIT / audit objects?)"
fi

if strings ossec-syscheckd | grep -q 'fim_audit_event'; then
    ok "audit adapter symbols present"
else
    fail "fim_audit_event not found in ossec-syscheckd"
fi

# Optional: BPF object build when host has BTF + toolchain (skipped in most containers).
if [[ -x syscheckd/ebpf/smoke_bpf_build.sh ]]; then
    if syscheckd/ebpf/smoke_bpf_build.sh; then
        ok "eBPF smoke script passed or skipped cleanly"
    else
        fail "eBPF smoke script failed"
    fi
fi

ok "syscheck audit build verification complete"
