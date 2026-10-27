#!/bin/sh

# Change these values!
# SLACKUSER user who posts notifications
# CHANNEL which channel it should be posted
# SITE is the URL provided by the Slack's WebHook, something like:
# https://hooks.slack.com/services/TOKEN"
SLACKUSER=""
CHANNEL=""
SITE=""
SOURCE="ossec2slack"

# Checking user arguments
if [ "x$1" = "xdelete" ]; then
    exit 0;
fi
ALERTID=$4
RULEID=$5
LOCAL=`dirname $0`;

# The alert text goes inside JSON strings: escape \ and "
json_escape() {
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# Logging
cd $LOCAL
cd ../
PWD=`pwd`
# Logging the call (ossec-execd sends our stdout/stderr to logs/active-responses.log)
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8"

# Checking for an alert id: anything in the execd queue can ask for this script,
# so accept "<time>.<offset>" only (no grep/awk options, patterns or escapes).
# agent_control -b uses the exact sentinel "(from_the_server)" with no alert text.
case "${ALERTID}" in
    "(from_the_server)")
        ALERTTITLE=""
        ALERTTEXT=""
        ;;
    ""|*[!0-9.]* )
        echo "`date` Unable to run active response (invalid alert id: '${ALERTID}')."
        exit 1
        ;;
    *)
        # We run as root and logs/alerts belongs to the ossec user, so alerts.log can be
        # a link to any file: pass on nothing but the record (the lines up to an empty
        # one) that starts with this alert's header.
        ALERT=`awk -v RS= -v id="** Alert ${ALERTID}:" 'index($0, id) == 1 { print; exit }' ${PWD}/../logs/alerts/alerts.log | head -n 11`
        ALERTTITLE=`printf '%s\n' "${ALERT}" | sed -n 2p | json_escape`
        ALERTTEXT=`printf '%s\n' "${ALERT}" | grep -v "Src IP: " | grep -v "User: " | grep "Rule: " -A 4 | cut -c -139 | json_escape`
        ;;
esac

LEVEL=`echo "${ALERTTEXT}" | head -1 | grep "(level [0-9]*)" | sed 's/^.*(level \([0-9]*\)).*$/\1/'`
COLOR="#D3D3D3"
if [ "${LEVEL}" ]
then
  [ "${LEVEL}" -ge 4 ] && COLOR="#FFCC00"
  [ "${LEVEL}" -ge 7 ] && COLOR="#FF9966"
  [ "${LEVEL}" -ge 12 ] && COLOR="#CC3300"
fi

PAYLOAD='{"channel": "'"$CHANNEL"'", "username": "'"$SLACKUSER"'", "attachments": [ {"fallback": "'"$( printf '%s\n%s' "${ALERTTITLE}" "${ALERTTEXT}" )"'", "title": "'"${ALERTTITLE}"'", "text": "'"${ALERTTEXT}"'", "color": "'"${COLOR}"'"} ]}'

# Command line arguments are visible to every local user (ps), so the alert
# goes to curl/wget in a file only root can read and the webhook URL on stdin.
POSTFILE=`mktemp ${PWD}/ossec-slack.XXXXXXXXXX`
if [ "X${POSTFILE}" = "X" ]; then
    echo "`date` $0: Unable to create a temporary file."
    exit 1;
fi
trap "rm -f ${POSTFILE}" 0
printf '%s' "${PAYLOAD}" > ${POSTFILE}

ls "`which curl`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "`which wget`" > /dev/null 2>&1
    if [ $? = 0 ]; then
        wget --keep-session-cookies --post-file=${POSTFILE} -i - <<EOF
${SITE}
EOF
        exit 0;
    fi
else
    curl -s -X POST --data-urlencode "payload@${POSTFILE}" -K - <<EOF
url = "${SITE}"
EOF
    exit 0;
fi

echo "`date` $0: Unable to find curl or wget."
exit 1;
