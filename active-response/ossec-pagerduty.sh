#!/bin/bash

# Change these values!
# APIKEY Your pagerduty api key

APIKEY="xxxxxxx"
# Checking user arguments
if [ "x$1" = "xdelete" ]; then
    exit 0;
fi
ALERTID=$4
RULEID=$5
LOCAL=`dirname $0`;
ALERTTIME=`echo "$ALERTID" | cut -d  "." -f 1`
ALERTLAST=`echo "$ALERTID" | cut -d  "." -f 2`

# The alert text goes inside a JSON string: escape \ and "
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
        ALERTFULL=""
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
        # One line, as it goes quoted into a JSON string below
        ALERTFULL=`printf '%s\n' "${ALERT}" | grep -v "Src IP: " | grep -v "User: " |grep "Rule: " -A 4 | cut -c -139 | json_escape | tr -s '[:space:]' ' ' | sed 's/ $//'`
        ;;
esac

ALERTLOG="${PWD}/../logs/alerts/alerts.log"

postfile=`mktemp`
if [ "X${postfile}" = "X" ]; then
    echo "`date` $0: Unable to create a temporary file."
    exit 1
fi
trap 'rm -f "${postfile}"' 0

# Quoted: the alert text comes from the logs and must not be split or glob-expanded.
# Use printf so backslashes from json_escape are not reinterpreted by echo.
printf '%s\n' '{ "service_key": "'"$APIKEY"'", "incident_key": "Alert: '"$ALERTTIME"' / Rule: '"$RULEID"'", "event_type": "trigger", "description": "OSSEC Alert: '"$ALERTLAST"'", "client": "OSSEC IDS", "client_url": "http://dcid.me/ossec", "details": { "location": "'"$HOSTNAME"'", "Rule":"'"$RULEID"'", "Description":"'"$ALERTFULL"'", "Log":"'"$ALERTLOG"'"} } ' > $postfile

curl -H "Content-type: application/json" -X POST --data @$postfile "https://events.pagerduty.com/generic/2010-04-15/create_event.json"
