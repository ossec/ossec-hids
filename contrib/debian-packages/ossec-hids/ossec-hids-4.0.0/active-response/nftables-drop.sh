#!/bin/sh
# Adds an IP to a nftables set
# Requirements: Linux with nftables
# Expect: srcip
# Author: Daniel B. Cid (iptables)
# Author: cgzones
# Author: ChristianBeer
# Last modified: Dec 26, 2021

# You need to create a set and a rule that uses it in order for packets to be dropped
# make sure the drop rules are checked before the accept rules
# Example:
# nft add set inet filter ossec_ar4 { type ipv4_addr\; comment \"ossec active response\" \; }
# nft add set inet filter ossec_ar6 { type ipv6_addr\; comment \"ossec active response\" \; }
# nft add rule inet filter input ip saddr @ossec_ar4 drop
# nft add rule inet filter input ip6 saddr @ossec_ar6 drop


UNAME=`uname`
ECHO="/bin/echo"
GREP="/bin/grep"
NFTCMD="/usr/sbin/nft"
RULE=""
ARG1=""
# protocol family used in nftables configuration
FAMILYIPV4="inet" # use "ip" when you have separate tables for ipv4 and ipv6
FAMILYIPV6="inet" # use "ip6" when you have separate tables for ipv4 and ipv6
# nftables table name
TABLEIPV4="filter"
TABLEIPV6="filter"
# Name of the sets where offending IPs should be added
SETIPV4="ossec_ar4"
SETIPV6="ossec_ar6"

RULEID=""
ACTION=$1
USER=$2
IP=$3
PWD=`pwd`
LOCK="${PWD}/nft-drop"
LOCK_PID="${PWD}/nft-drop/pid"


LOCAL=`dirname $0`;
cd $LOCAL
cd ../
filename=$(basename "$0")

LOG_FILE="${PWD}/../logs/active-responses.log"

echo "`date` $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>"
   exit 1;
fi

case "${IP}" in
    *:* ) RULE="element ${FAMILYIPV6} ${TABLEIPV6} ${SETIPV6} { ${IP} }";;
    *.* ) RULE="element ${FAMILYIPV4} ${TABLEIPV4} ${SETIPV4} { ${IP} }";;
    * ) echo "`date` Unable to run active response (invalid IP: '${IP}')." >> ${LOG_FILE} && exit 1;;
esac

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
            kill="false"
            for pid in `pgrep -f "${filename}"`; do
                if [ "x${pid}" = "x${C_PID}" ]; then
                    # Unlocking and exiting
                    kill -9 ${C_PID}
                    echo "`date` Killed process ${C_PID} holding lock." >> ${LOG_FILE}
                    kill="true"
                    unlock;
                    i=0;
                    S_PID="";
                    break;
                fi
            done

            if [ "x${kill}" = "xfalse" ]; then
                echo "`date` Unable kill process ${C_PID} holding lock." >> ${LOG_FILE}
                # Unlocking and exiting
                unlock;
                exit 1;
            fi
        fi
    done
}

# Unlock function
unlock()
{
   rm -rf ${LOCK}
}



# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: invalid action: ${ACTION}"
   exit 1;
fi



# We should run on linux
if [ "X${UNAME}" = "XLinux" ]; then
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="add"
   else
      ARG1="delete"
   fi

   # Checking if nft is present
   if [ ! -x ${NFTCMD} ]; then
      NFTCMD="/usr"${NFTCMD}
      if [ ! -x ${NFTCMD} ]; then
        echo "$0: can not find nft"
        exit 1;
      fi
   fi

   # Executing and exiting
   COUNT=0;
   lock;
   while [ 1 ]; do
        ${NFTCMD} ${ARG1} ${RULE} >/dev/null
        RES=$?
        if [ $RES = 0 ]; then
            break;
        else
            COUNT=`expr $COUNT + 1`;
            echo "`date` Unable to run (nft returning $RES): $COUNT - $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}
            sleep $COUNT;

            if [ $COUNT -gt 4 ]; then
                break;
            fi
        fi
   done
   unlock;

   exit 0;
else
   exit 0;
fi
