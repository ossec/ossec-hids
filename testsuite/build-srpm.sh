#!/bin/bash
# Generate a source RPM (.src.rpm) for ossec-hids. You can then test with:
#   mock -r fedora-43-x86_64 rebuild ossec-hids-*.src.rpm
#   rpmbuild --rebuild ossec-hids-*.src.rpm
# Run from repo root: ./testsuite/build-srpm.sh
# Requires: rpmbuild. The spec expects only Source0 (tarball); the tarball
# is created from the current tree (tar from disk), so untracked files are included.
# If rpmbuild fails with "Illegal char '-'" in Release, some rpm versions reject
# hyphens in the Release tag; use a numeric release in the spec for local builds.
set -e -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if ! command -v rpmbuild &>/dev/null; then
    echo "Error: rpmbuild is required (e.g. rpm-build package)." >&2
    exit 1
fi

if [[ ! -f "$ROOT_DIR/ossec-hids.spec" ]]; then
    echo "Error: ossec-hids.spec not found at $ROOT_DIR" >&2
    exit 1
fi

if [[ ! -d "$ROOT_DIR/src" ]] || [[ ! -f "$ROOT_DIR/ossec-hids.spec" ]]; then
    echo "Error: Expected repo root with src/ and ossec-hids.spec." >&2
    exit 1
fi

VERSION=$(sed -n 's/^Version:[[:space:]]*//p' "$ROOT_DIR/ossec-hids.spec" | head -1)
NAME="ossec-hids"
TARBALL="${NAME}-${VERSION}.tar.gz"

if [[ -z "$VERSION" ]]; then
    echo "Error: Could not read Version from ossec-hids.spec" >&2
    exit 1
fi

OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"
mkdir -p "$OUT_DIR"

# Use a temp dir for SPECS/SOURCES/SRPMS so we don't clutter the repo
TOP=$(mktemp -d)
trap "rm -rf '$TOP'" EXIT
mkdir -p "$TOP"/{SPECS,SOURCES,SRPMS}

echo "Building source RPM for $NAME $VERSION"
echo "Root: $ROOT_DIR"

cd "$ROOT_DIR"
# Tarball from current tree (includes untracked files), same layout as git archive
tar -czf "$TOP/SOURCES/$TARBALL" --exclude='.git' --exclude="$TARBALL" \
    --transform "s,^\./,$NAME-$VERSION/," .
cp ossec-hids.spec "$TOP/SPECS/"

rpmbuild -bs \
    --define "_topdir $TOP" \
    "$TOP/SPECS/ossec-hids.spec"

SRPM=$(echo "$TOP/SRPMS/"*.src.rpm)
if [[ ! -f "$SRPM" ]]; then
    echo "Error: No .src.rpm was produced." >&2
    exit 1
fi

cp "$SRPM" "$OUT_DIR/"
echo "SUCCESS: source RPM written to $OUT_DIR/$(basename "$SRPM")"
echo "Test with: mock -r <config> rebuild $OUT_DIR/$(basename "$SRPM")"
echo "       or: rpmbuild --rebuild $OUT_DIR/$(basename "$SRPM")"
