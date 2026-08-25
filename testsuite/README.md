# OSSEC test suite

**Engine roadmap:** [`analysisd-detection-improvement-plan.md`](analysisd-detection-improvement-plan.md) — sequential detection improvement plan for `analysisd` (planning; not yet implemented).

Run build tests in Podman (no host installs). From the **repo root**:

```bash
./testsuite/build-test/build.sh           # all distros
./testsuite/build-test/build.sh fedora-43  # single distro
```

By default, `build.sh` and `build-deb.sh` use `PODMAN_PLATFORM=linux/amd64` so images and compiles target x86_64 (override with e.g. `PODMAN_PLATFORM=linux/arm64` if needed).

With no argument, loops over every distro in `testsuite/build-test/` (centos-7, debian-13, fedora-43/44, rockylinux-8/9/10, ubuntu-20.04/24.04/26.04, windows-cross). For each distro it builds the container image from that distro’s `Containerfile`, then:

1. **Agent build** with `USE_AUDIT=yes` (FIM auditd code path + adapter)
2. **Server build** with the same flags (full server target still includes syscheckd)

Optional post-build checks (off by default): set `TEST=1` to run:

- **Agent:** [`verify-syscheck-audit.sh`](build-test/verify-syscheck-audit.sh) — `ossec-syscheckd` links audit symbols (`audit_init`, `fim_audit_event`)
- **Server:** [`verify-jsonout-default.sh`](build-test/verify-jsonout-default.sh) — `jsonout_output` defaults on when `<jsonout_output>` is omitted, and `no` still disables it

```bash
TEST=1 ./testsuite/build-test/build.sh fedora-43
```

Goal: confirm agents/servers **build** with audit enabled and system **libaudit** / **libbpf** headers installed. eBPF BPF `.o` objects are built only when the container has `bpftool`, `clang`, and kernel BTF (`smoke_bpf_build.sh` skips otherwise).

### Linux container dependencies (audit FIM)

| Family | Packages added to `Containerfile` |
|--------|-----------------------------------|
| Fedora / Rocky | `audit-libs-devel`, `libbpf-devel`, `clang`, `llvm`, `bpftool`, `pkgconfig` |
| CentOS 7 | `audit-libs-devel` only (no libbpf toolchain) |
| Debian | `libaudit-dev`, `libbpf-dev`, `clang`, `llvm`, `bpftool`, `pkg-config` |
| Ubuntu | `libaudit-dev`, `libbpf-dev`, `clang`, `llvm`, `linux-tools-common` (provides `bpftool`), `pkg-config` |

Make flags in CI containers: `USE_AUDIT=yes USE_CURL=yes USE_MAGIC=no`.

**Source RPM** (from repo root):

```bash
./testsuite/build-srpm.sh
```

Builds a `.src.rpm` only: creates the source tarball with `git archive`, runs `rpmbuild -bs`. Output goes to `testsuite/` (or set `OUT_DIR`). Requires `rpmbuild` and `git`. Then test the spec ad hoc with mock or rpmbuild:

```bash
mock -r fedora-43-x86_64 rebuild testsuite/ossec-hids-*.src.rpm
# or
rpmbuild --rebuild testsuite/ossec-hids-*.src.rpm
```

The tree must have the packaging files in `contrib/specs/` (e.g. `filter-requires.sh`, `ossec-hids-hybrid.conf`, `ossec-hids.logrotate`, `ossec-authd`) for a full rebuild to succeed.

**Debian packages** (from repo root, uses Podman):

```bash
./testsuite/build-deb.sh                    # build ossec-hids-agent .deb (default)
./testsuite/build-deb.sh ossec-hids        # build server .deb
./testsuite/build-deb.sh all                # build both agent and server
```

Builds in an `ubuntu:24.04` (noble) container (set `DEB_DIST` or `DEB_IMAGE` to use another suite/image, e.g. `DEB_DIST=bookworm DEB_IMAGE=docker.io/library/debian:bookworm ./testsuite/build-deb.sh`). Output: `.deb`, `.changes`, and `.buildinfo` in `testsuite/` (or set `OUT_DIR`). Requires `podman`. Debian build deps include `libaudit-dev` and `libbpf-dev` for FIM audit support.

### Manual verify (on a built tree)

From `src/` after `make TARGET=agent USE_AUDIT=yes`:

```bash
../testsuite/build-test/verify-syscheck-audit.sh .
syscheckd/ebpf/smoke_bpf_build.sh   # optional; needs BTF on host
```

### Unit / regression tests (host, after build)

From `src/` after `make TARGET=server` (or `hybrid`):

```bash
make regression                 # shared/tests + analysisd regressions
make -C shared/tests check      # queue_op / thread_pool / helpers only
make -f tests/regressions/Makefile check
```

`make regression` covers EventList sharding, frequency `last_events` ownership,
sid-list overflow free-safety, auth IPv6 key handling, and `os_queue` timedwait
(used by the always-on analysisd pipeline). See
[`src/tests/regressions/README.md`](../src/tests/regressions/README.md).
