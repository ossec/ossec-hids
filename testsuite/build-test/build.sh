#!/bin/bash
set -u

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$BASE_DIR")")"
FAILURES=0

echo "Starting build test suite..."
echo "Root Dir: $ROOT_DIR"

# Ensure we have podman
if ! command -v podman &> /dev/null; then
    echo "Error: podman could not be found."
    exit 1
fi

for distro_dir in "$BASE_DIR"/*/; do
    # Remove trailing slash
    distro_dir="${distro_dir%/}"
    distro_name=$(basename "$distro_dir")
    
    # Skip non-directories or hidden files just in case
    if [[ ! -d "$distro_dir" ]]; then continue; fi

    echo "------------------------------------------------"
    echo "Testing build for: $distro_name"
    
    # Sanitize image name
    image_name="build-test-${distro_name//./-}"
    
    echo "Building container image: $image_name"
    if ! podman build -t "$image_name" "$distro_dir"; then
        echo "FAILED: Container build for $distro_name failed."
        ((FAILURES++))
        continue
    fi
    
    echo "Running compilation on $distro_name..."
    # We run make clean first to ensure a fresh build, then build server target.
    # Using -v with :Z to handle SELinux if present.
    # cd src is required because the Makefile is in src/
    
    BUILD_TARGET="server"
    if [ "$distro_name" == "windows-cross" ]; then
        echo "Building Windows agent (Cross-compiling)..."
        # Download missing PCRE2 source for Windows build
        if ! podman run --rm -v "$ROOT_DIR:/src_origin:Z" "$image_name" /bin/sh -c "
            mkdir -p /src && cp -r /src_origin/* /src/ && \
            cd /src/src/external && \
            wget -q https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.32/pcre2-10.32.tar.gz && \
            tar xzf pcre2-10.32.tar.gz && \
            cd /src/src && \
            make clean && \
            make TARGET=winagent -j$(nproc)"; then
            
            echo "FAILED: Compilation for $distro_name failed."
            ((FAILURES++))
        else
            echo "SUCCESS: $distro_name passed."
        fi
        continue
    fi

    if ! podman run --rm -v "$ROOT_DIR:/src:Z" "$image_name" /bin/sh -c "cd src && make clean && make TARGET=$BUILD_TARGET -j$(nproc)"; then
        echo "FAILED: Compilation for $distro_name failed."
        ((FAILURES++))
    else
        echo "SUCCESS: $distro_name passed."
    fi
done

if [ "$FAILURES" -eq 0 ]; then
    echo "------------------------------------------------"
    echo "All tests passed successfully!"
    exit 0
else
    echo "------------------------------------------------"
    echo "$FAILURES tests failed."
    exit 1
fi
