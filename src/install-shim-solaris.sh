#!/bin/ksh
#
# GNU-install subset for Solaris. /usr/sbin/install is the SVR4 script, which
# searches the system for a file named "null" when given /dev/null and reports
# "ossec-logcollector was not found anywhere" for a binary in the build
# directory (issue #2016). Used when no GNU install is on the system.
#

mode=755
owner=
group=
backup=0
directories=0

while getopts "m:o:g:bd" opt; do
    case "$opt" in
        m) mode=$OPTARG ;;
        o) owner=$OPTARG ;;
        g) group=$OPTARG ;;
        b) backup=1 ;;
        d) directories=1 ;;
        *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))

apply_meta() {
    if [ -n "$owner" ] || [ -n "$group" ]; then
        chown "${owner}:${group}" "$1" || exit 1
    fi
    chmod "$mode" "$1" || exit 1
}

backup_file() {
    if [ "$backup" -eq 1 ] && [ -f "$1" ]; then
        cp -p "$1" "$1~" || exit 1
    fi
}

if [ "$directories" -eq 1 ]; then
    [ $# -ge 1 ] || exit 2
    for directory in "$@"; do
        mkdir -p "$directory" || exit 1
        apply_meta "$directory"
    done
    exit 0
fi

if [ $# -lt 2 ]; then
    echo "install-shim-solaris: need a source and a destination" >&2
    exit 2
fi

sources=()
while [ $# -gt 1 ]; do
    sources+=("$1")
    shift
done
dest=$1

if [ "${#sources[@]}" -gt 1 ] && [ ! -d "$dest" ]; then
    echo "install-shim-solaris: destination is not a directory: $dest" >&2
    exit 1
fi

for source in "${sources[@]}"; do
    if [ -d "$dest" ]; then
        target="$dest/${source##*/}"
    else
        target=$dest
    fi
    backup_file "$target"
    cp -f "$source" "$target" || exit 1
    apply_meta "$target"
done

exit 0
