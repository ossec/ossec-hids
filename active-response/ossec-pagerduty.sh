#!/bin/bash -x

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

# Logging
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log
ALERTFULL=`grep -A 10 "$ALERTTIME" ${PWD}/../logs/alerts/alerts.log | grep -v "\.$ALERTLAST: " -A 10 | grep -v "Src IP: " | grep -v "User: " |grep "Rule: " -A 4 | cut -c -139 | sed 's/\"//g'`

ALERTLOG= ${PWD}/../logs/alerts/alerts.log 

postfile=`mktemp`

echo '{ "service_key": "'$APIKEY'", "incident_key": "Alert: '$ALERTTIME' / Rule: '$RULEID'", "event_type": "trigger", "description": "OSSEC Alert: '$ALERTLAST'", "client": "OSSEC IDS", "client_url": "http://dcid.me/ossec", "details": { "location": "'$HOSTNAME'", "Rule":"'$RULEID'", "Description":"'$ALERTFULL'", "Log":"'$ALERTLOG'"} } ' > $postfile

curl -H "Content-type: application/json" -X POST --data @$postfile "https://events.pagerduty.com/generic/2010-04-15/create_event.json"
