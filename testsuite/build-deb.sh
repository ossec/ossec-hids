#!/bin/bash
# Build Debian packages for ossec-hids in a Podman container (like build-srpm.sh for RPM).
# Run from repo root: ./testsuite/build-deb.sh [ossec-hids-agent|ossec-hids|all]
# Default: ossec-hids-agent. Output: testsuite/*.deb (and .changes, .buildinfo).
# Requires: podman. Uses ubuntu:24.04 (noble) by default (set DEB_DIST to override).
set -e -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGE="${1:-ossec-hids-agent}"
VERSION="${VERSION:-4.0.0}"
DEB_DIST="${DEB_DIST:-noble}"
DEB_IMAGE="${DEB_IMAGE:-docker.io/library/ubuntu:24.04}"
PODMAN_PLATFORM="${PODMAN_PLATFORM:-linux/amd64}"
NAME="ossec-hids"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"

if ! command -v podman &>/dev/null; then
    echo "Error: podman is required." >&2
    exit 1
fi

if [[ ! -d "$ROOT_DIR/contrib/debian-packages" ]] || [[ ! -d "$ROOT_DIR/src" ]]; then
    echo "Error: Expected repo root with contrib/debian-packages/ and src/." >&2
    exit 1
fi

if [[ "$PACKAGE" != "ossec-hids-agent" && "$PACKAGE" != "ossec-hids" && "$PACKAGE" != "all" ]]; then
    echo "Usage: $0 [ossec-hids-agent|ossec-hids|all]" >&2
    exit 1
fi

# Read version from spec if present
if [[ -f "$ROOT_DIR/ossec-hids.spec" ]]; then
    SPEC_VER=$(sed -n 's/^Version:[[:space:]]*//p' "$ROOT_DIR/ossec-hids.spec" | head -1)
    [[ -n "$SPEC_VER" ]] && VERSION="$SPEC_VER"
fi

mkdir -p "$OUT_DIR"
TARBALL="${NAME}-${VERSION}.tar.gz"

echo "Building Debian package(s) for $NAME $VERSION (dist: $DEB_DIST)"
echo "Package(s): $PACKAGE"
echo "Root: $ROOT_DIR"

# Build in container: create tarball from repo, then build .deb
podman run --rm --platform "$PODMAN_PLATFORM" \
    -v "$ROOT_DIR:/source:ro" \
    -v "$OUT_DIR:/output:rw" \
    -e PACKAGE="$PACKAGE" \
    -e VERSION="$VERSION" \
    -e NAME="$NAME" \
    -e DEB_DIST="$DEB_DIST" \
    "$DEB_IMAGE" \
    bash -c '
        set -e
        TARBALL="${NAME}-${VERSION}.tar.gz"
        apt-get -qq update
        apt-get -qq install -y build-essential devscripts debhelper libssl-dev linux-libc-dev \
            libpcre2-dev libevent-dev zlib1g-dev libsystemd-dev libmagic-dev \
            libaudit-dev libbpf-dev clang llvm linux-tools-common pkg-config patch
        cd /tmp
        mkdir -p work && cd work
        # Tarball from repo (same layout as build-srpm: prefix name-version)
        tar -czf "$TARBALL" -C /source --exclude=.git --exclude="$TARBALL" \
            --transform "s,^\./,$NAME-$VERSION/," .
        build_one() {
            local pkg="$1"
            local dir="${pkg}-${VERSION}"
            rm -rf "$dir" "${pkg}_${VERSION}.orig.tar.gz"
            tar -xzf "$TARBALL"
            mv "$NAME-$VERSION" "$dir"
            cp -r "/source/contrib/debian-packages/$pkg/debian" "$dir/"
            # Apply patches in series order
            if [[ -f "$dir/debian/patches/series" ]]; then
                while read -r patch; do
                    [[ -z "$patch" || "$patch" =~ ^# ]] && continue
                    patch -d "$dir" -p1 < "$dir/debian/patches/$patch" || true
                done < "$dir/debian/patches/series"
            fi
            tar -czf "${pkg}_${VERSION}.orig.tar.gz" "$dir"
            cd "$dir"
            dpkg-buildpackage -b -us -uc -d
            cd ..
            mv ${pkg}_*.deb ${pkg}_*.changes ${pkg}_*.buildinfo /output/ 2>/dev/null || true
        }
        if [[ "$PACKAGE" == "all" ]]; then
            build_one ossec-hids-agent
            build_one ossec-hids
        else
            build_one "$PACKAGE"
        fi
    '

echo "SUCCESS: .deb (and .changes, .buildinfo) written to $OUT_DIR/"
ls -la "$OUT_DIR"/*.deb "$OUT_DIR"/*.changes 2>/dev/null || true
ls -la "$OUT_DIR"/*.buildinfo 2>/dev/null || true
