#!/bin/sh
# Adds an IP to an existing IPSet in AWS Web Application Firewall
# Requirements: Linux with aws installed and configured
# Expect: srcip
# Author: Midi12
# Last modified: Feb 25, 2020

# Change this values
IPSETID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" # target ip set identifier
REGION="xx-xxxx-x" # target waf region
IS_REGIONAL=1 # put 0 to use waf or 1 to use waf-regional

# Setup
if ! [ -x "$(command -v aws)" ]; then
        echo "aws cli is not installed" >&2
        exit 1;
fi

AWS=$(command -v aws)
PWD=`pwd`
LOCAL=`dirname $0`
ACTION=$1
IP=$2
P_REGION=""
P_IPTYPE=""
P_ACTION=""
P_CHGTKN=""
P_RESP=""

cd $LOCAL
cd ../

FILENAME=$(basename "$0")
LOGFILE="${PWD}/../logs/active-responses.log"

echo "`date` $0 $1 $2 $3 $4 $5" >> ${LOGFILE}

# Check for an action
if [ "x${ACTION}" = "x" ]; then
        echo "$0: <action> <ip>" >&2
        exit 1;
fi

# Check for an IP
if [ "x${IP}" = "x" ]; then
        echo "$0: <action> <ip>" >&2
        exit 1;
fi

# Determining regional
case "${IS_REGIONAL}" in
        0 ) P_REGION="waf";;
        1 ) P_REGION="waf-regional";;
        * ) echo "`date` Unable to run active response (ill-formed parameter: IS_REGIONAL '${IS_REGIONAL}'" >> ${LOGFILE} && exit 1;;
esac

# Determining action
case "${ACTION}" in
        ADD|add ) P_ACTION="INSERT";;
        DEL|del ) P_ACTION="DELETE";;
        * ) echo "`date` Unable to run active response (ill-formed argument Action: '${ACTION}'" >> ${LOGFILE} && exit 1;;
esac

# Determining IP type
case "${IP}" in
        *:* ) P_IPTYPE="IPV6";;
        *.* ) P_IPTYPE="IPV4";;
        * ) echo "`date` Unable to run active response (ill-formed argument IP: '${IP}')" >> ${LOGFILE} && exit 1;;esac

P_CHGTKN="$(${AWS} ${P_REGION} get-change-token --region ${REGION} --output text)"

P_RESP="$(${AWS} ${P_REGION} update-ip-set --ip-set-id ${IPSETID} --change-token ${P_CHGTKN} --updates Action=\"${P_ACTION}\",IPSetDescriptor=\{Type="${P_IPTYPE}",Value="${IP}/32"\} --region $REGION --output text)"

if [ "${P_RESP}" != "${P_CHGTKN}" ]; then
        echo "`date` Failed to update waf ipset: '${P_ACTION} ${IP} ${P_RESP}'" >> ${LOGFILE}
        exit 1;
fi

echo "Action ${ACTION} on IP ${IP} succeed"

