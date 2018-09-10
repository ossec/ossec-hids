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

# Logging
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log
ALERTTITLE=`grep -A 1 "$ALERTID" ${PWD}/../logs/alerts/alerts.log | tail -1`
ALERTTEXT=`grep -A 10 "$ALERTID" ${PWD}/../logs/alerts/alerts.log | grep -v "Src IP: " | grep -v "User: " | grep "Rule: " -A 4 | sed '/^$/Q' | cut -c -139 | sed 's/\"//g'`

LEVEL=`echo "${ALERTTEXT}" | head -1 | grep "(level [0-9]*)" | sed 's/^.*(level \([0-9]*\)).*$/\1/'`
COLOR="#D3D3D3"
if [ "${LEVEL}" ]
then
  [ "${LEVEL}" -ge 4 ] && COLOR="#FFCC00"
  [ "${LEVEL}" -ge 7 ] && COLOR="#FF9966"
  [ "${LEVEL}" -ge 12 ] && COLOR="#CC3300"
fi

PAYLOAD='{"channel": "'"$CHANNEL"'", "username": "'"$SLACKUSER"'", "attachments": [ {"fallback": "'"$( printf "${ALERTTITLE}\n${ALERTTEXT}" )"'", "title": "'"${ALERTTITLE}"'", "text": "'"${ALERTTEXT}"'", "color": "'"${COLOR}"'"} ]}'

ls "`which curl`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "`which wget`" > /dev/null 2>&1
    if [ $? = 0 ]; then
        wget --keep-session-cookies --post-data="${PAYLOAD}" ${SITE} 2>>${PWD}/../logs/active-responses.log
        exit 0;
    fi
else
    curl -s -X POST --data-urlencode "payload=${PAYLOAD}" ${SITE} 2>>${PWD}/../logs/active-responses.log
    exit 0;
fi

echo "`date` $0: Unable to find curl or wget." >> ${PWD}/../logs/active-responses.log
exit 1;
