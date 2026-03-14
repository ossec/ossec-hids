#!/bin/sh
# Wrapper for RPM dependency detection. Passes through to the system find-requires.
# Customize to filter unwanted requires if needed.
if [ -x /usr/lib/rpm/redhat/find-requires ]; then
    exec /usr/lib/rpm/redhat/find-requires "$@"
fi
if [ -x /usr/lib/rpm/find-requires ]; then
    exec /usr/lib/rpm/find-requires "$@"
fi
# Fallback: no-op (avoid breaking the build)
exec cat
