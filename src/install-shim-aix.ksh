#!/bin/ksh
#
# Wrapper for install on AIX, handling -b and -d options
#

# AIX defaults
mode="755"
owner="bin"
group="bin"

backup=""
directories=0

while getopts "m:M:o:O:g:G:bd" opt; do
    case "$opt" in
    m|M) mode=$OPTARG ;;
    o|O) owner=$OPTARG ;;
    g|G) group=$OPTARG ;;
    b)   backup="-o" ;;
    d)   directories=1 ;;
    esac
done

shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

if [ "${directories}" -eq 1 ]; then
  for directory in $@; do
    mkdir -p "${directory}"
    chown ${owner}:${group} "${directory}"
    chmod ${mode} "${directory}"
  done
else
  sources=""
  destination=""
  while [ -n "$1" ]; do
    destination="$1"
    shift
    [ -n "$1" ] && sources="${sources} $destination"
  done
  for source in $sources; do
    if [ ! -d "${destination}" -o "${source}" == "/dev/null" ]; then
      # need to manually copy the file if the target includes the filename or the source is null
      cp "${source}" "${destination}"
      chown ${owner}:${group} "${destination}"
      chmod ${mode} "${destination}"
    else
      install -M ${mode} -O ${owner} -G ${group} -f "${destination}" "${backup}" "${source}" || exit $? 
    fi
  done
fi

exit 0
