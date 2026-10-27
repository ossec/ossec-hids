#!/bin/sh
# Adds an IP to the IPFW drop list.
# Only works with IPFW.
# Expect: srcip
# Author: Rafael Capovilla - under @ ( at ) underlinux.com.br
# Author: Daniel B. Cid - dcid @ ( at ) ossec.net
# Author: Charles W. Kefauver ckefauver @ ( at ) ibacom.es
#         changed for Mac OS X compatibility
# Last modified: August 14, 2006

UNAME=`uname`
IPFW="/sbin/ipfw"
ARG1=""
ARG2=""
ACTION=$1
USER=$2
IP=$3

# warning do NOT add leading 0 in SET_ID
SET_ID=2

# "ipfw delete <number>" removes every rule that has that number, so each
# blocked IP gets a rule number of its own out of this range (numbers that
# are already in use are skipped). ipfw checks the rules in number order,
# so the range must come before the rules that allow traffic.
FIRST_RULE_ID=100
LAST_RULE_ID=999

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
LOCK="${PWD}/ipfw_mac-lock"
LOCK_PID="${PWD}/ipfw_mac-lock/pid"
# Logging the call (ossec-execd sends our stdout/stderr to logs/active-responses.log)
echo "`date` $0 $1 $2 $3 $4 $5"


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>" 
   exit 1;
fi

# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: Invalid action: ${ACTION}"
   exit 1;
fi


# This number should be more than enough (even if a hundred
# instances of this script is ran together). If you have
# a really loaded env, you can increase it to 75 or 100.
MAX_ITERATION="50"


# Lock function
lock()
{
    i=0;
    # Providing a lock.
    while [ 1 ]; do
        mkdir ${LOCK} > /dev/null 2>&1
        MSL=$?
        if [ "${MSL}" = "0" ]; then
            # Lock acquired (setting the pid)
            echo "$$" > ${LOCK_PID}
            return;
        fi

        # Getting currently/saved PID locking the file
        C_PID=`cat ${LOCK_PID} 2>/dev/null`
        if [ "x" = "x${S_PID}" ]; then
            S_PID=${C_PID}
        fi

        # Breaking out of the loop after X attempts
        if [ "x${C_PID}" = "x${S_PID}" ]; then
            i=`expr $i + 1`;
        fi

        sleep $i;

        i=`expr $i + 1`;

        # So i increments 2 by 2 if the pid does not change.
        # If the pid keeps changing, we will increments one
        # by one and fail after MAX_ITERACTION
        if [ "$i" = "${MAX_ITERATION}" ]; then
            # Leave the lock in place: removing it while another instance holds
            # the critical section lets two adds pick the same rule number.
            echo "`date` Unable to execute. Locked: $0"
            exit 1;
        fi
    done
}

# Unlock function
unlock()
{
    rm -rf ${LOCK}
}


# We should run on Darwin
if [ "X${UNAME}" = "XDarwin" ]; then
   ls ${IPFW} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi

   
   # Executing and exiting
	if [ "x${ACTION}" = "xadd" ]; then
	   #${IPFW} set disable ${SET_ID}
	   # Only one instance at a time may pick a rule number, or two
	   # IPs would end up sharing one. Disabled sets are listed with
	   # a "# DISABLED" prefix; their numbers are in use as well.
	   lock;
	   RULE_ID=`${IPFW} -S list | sed 's/^# DISABLED //' | awk -v id=${FIRST_RULE_ID} '$1 + 0 == id {id++} END {print id}'`
	   if [ ${RULE_ID} -gt ${LAST_RULE_ID} ]; then
	       unlock;
	       echo "`date` Unable to run active response (no free ipfw rule number for '${IP}')."
	       exit 1;
	   fi
	   ${IPFW} -q add ${RULE_ID} set ${SET_ID} deny ip from ${IP} to any
	   ${IPFW} -q add ${RULE_ID} set ${SET_ID} deny ip from any to ${IP}
	   ${IPFW} -q set enable ${SET_ID}
	   unlock;
	   exit 0;
	fi

	if [ "x${ACTION}" = "xdelete" ]; then
		# Both rules of an IP share one ID. Match whole tokens so a shorter
		# address (10.1.1.1) cannot select 10.1.1.10, and "set 2" cannot
		# select "set 20".
		RULES_TO_DELETE=`${IPFW} -S show | awk -v sid="set ${SET_ID}" -v ip="${IP}" '
			index($0, " " sid " ") {
				for (i = 1; i <= NF; i++)
					if (($i == "from" || $i == "to") && $(i+1) == ip) {
						print $1;
						break
					}
			}' | sort -u`
		
		for RULE_ID in ${RULES_TO_DELETE}
		do
			${IPFW} -q delete ${RULE_ID}
		done
		
		exit 0;
	fi

   exit 0;
fi


# Not Darwin
exit 1;
