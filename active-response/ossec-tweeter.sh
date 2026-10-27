#!/bin/sh
# Tweeter an alert - copy at /var/ossec/active-response/bin/ossec-tweeter.sh
# Author: Daniel Cid


# Change these values!
TWITTERUSER=""
TWITTERPASS=''
DIRECTMSGUSER=""
SOURCE="ossec2tweeter"



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
        ALERTFULL=`printf '%s\n' "${ALERT}" | grep -v "Src IP: " | grep -v "User: " |grep "Rule: " -A 4 | cut -c -139`
        ;;
esac



# Checking if we are sending direct message or not.
if [ "x" = "x$DIRECTMSGUSER" ]; then
    SITE="http://twitter.com/statuses/update.xml"
    REQUESTUSER=""
    REQUESTMSG="status=$ALERTFULL"
else
    SITE="http://twitter.com/direct_messages/new.xml"
    REQUESTUSER="user=$DIRECTMSGUSER&"
    REQUESTMSG="text=$ALERTFULL"
fi    


# Command line arguments are visible to every local user (ps), so the alert
# and the credentials go to curl/wget in files only root can read.
POSTFILE=`mktemp ${PWD}/ossec-tweeter.XXXXXXXXXX`
AUTHFILE=`mktemp ${PWD}/ossec-tweeter.XXXXXXXXXX`
if [ "X${POSTFILE}" = "X" -o "X${AUTHFILE}" = "X" ]; then
    echo "`date` $0: Unable to create a temporary file."
    exit 1;
fi
trap "rm -f ${POSTFILE} ${AUTHFILE}" 0
printf '%s' "source=$SOURCE&$REQUESTUSER$REQUESTMSG" > ${POSTFILE}

ls "`which curl`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "`which wget`" > /dev/null 2>&1
    if [ $? = 0 ]; then
        printf 'http_user = %s\nhttp_password = %s\n' "$TWITTERUSER" "$TWITTERPASS" > ${AUTHFILE}
        WGETRC=${AUTHFILE} wget --keep-session-cookies --post-file=${POSTFILE} $SITE
        exit 0;
    fi    
else
    # curl's config syntax: quotes and backslashes in the value are escaped
    printf '%s\n' "$TWITTERUSER:$TWITTERPASS" | sed 's/[\\"]/\\&/g; s/.*/user = "&"/' > ${AUTHFILE}
    curl -K ${AUTHFILE} --data-binary @${POSTFILE} $SITE
    exit 0;
fi    

echo "`date` $0: Unable to find curl or wget."
exit 1;
