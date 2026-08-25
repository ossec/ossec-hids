#!/bin/sh
# Adds an IP to the iptables drop list (if linux)
# Adds an IP to the ipfilter drop list (if solaris, freebsd or netbsd)
# Adds an IP to the ipsec drop list (if aix)
# Requirements: Linux with iptables, Solaris/FreeBSD/NetBSD with ipfilter or AIX with IPSec
# Expect: srcip
# Author: Ahmet Ozturk (ipfilter and IPSec)
# Author: Daniel B. Cid (iptables)
# Author: cgzones
# Last modified: Aug 04, 2026
#
# Linux iptables: drops are inserted into a dedicated OSSEC chain (#678) so
# configuration-management tools that purge unmanaged INPUT/FORWARD rules do
# not remove active-response blocks. The script creates the chain and a jump
# from INPUT (and FORWARD when IP forwarding is enabled) if missing.
# Override the chain name with OSSEC_FW_CHAIN if needed.

UNAME=`uname`
ECHO="/bin/echo"
GREP="/bin/grep"
IPTABLES=""
IP4TABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
IPFILTER="/sbin/ipf"
if [ "X$UNAME" = "XSunOS" ]; then
    IPFILTER="/usr/sbin/ipf"
fi
GENFILT="/usr/sbin/genfilt"
LSFILT="/usr/sbin/lsfilt"
MKFILT="/usr/sbin/mkfilt"
RMFILT="/usr/sbin/rmfilt"
ARG=""
RULEID=""
ACTION=$1
USER=$2
IP=$3
# Dedicated chain for AR drops (iptables/ip6tables). Configurable for #678.
CHAIN="${OSSEC_FW_CHAIN:-OSSEC}"
PWD=`pwd`
LOCK="${PWD}/fw-drop"
LOCK_PID="${PWD}/fw-drop/pid"
IPV4F="/proc/sys/net/ipv4/ip_forward"
IPV6F="/proc/sys/net/ipv6/conf/all/forwarding"

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
    *:* ) IPTABLES=$IP6TABLES;;
    *.* ) IPTABLES=$IP4TABLES;;
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

# Return 0 if parent chain already jumps to ${CHAIN}.
ossec_jump_present()
{
    parent="$1"
    if ${IPTABLES} -C "${parent}" -j "${CHAIN}" >/dev/null 2>&1; then
        return 0
    fi
    # iptables without -C reports "Bad argument"; fall back to listing.
    if ${IPTABLES} -C "${parent}" -j "${CHAIN}" 2>&1 | ${GREP} -qi "Bad argument"; then
        ${IPTABLES} -n -L "${parent}" 2>/dev/null | ${GREP} -Eq "^${CHAIN}[[:space:]]"
        return $?
    fi
    return 1
}

# Ensure dedicated OSSEC chain exists and is jumped to from INPUT (/FORWARD).
ensure_ossec_chain()
{
    ${IPTABLES} -n -L "${CHAIN}" >/dev/null 2>&1 || ${IPTABLES} -N "${CHAIN}"

    ossec_jump_present INPUT || ${IPTABLES} -I INPUT -j "${CHAIN}"

    if [ -e "$IPV4F" ]; then
        IPV4KEY="$(cat "$IPV4F")"
    else
        IPV4KEY="0"
    fi
    if [ -e "$IPV6F" ]; then
        IPV6KEY="$(cat "$IPV6F")"
    else
        IPV6KEY="0"
    fi

    if [ "$IPV4KEY" != "0" ] || [ "$IPV6KEY" != "0" ]; then
        ossec_jump_present FORWARD || ${IPTABLES} -I FORWARD -j "${CHAIN}"
    fi
}


# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: invalid action: ${ACTION}"
   exit 1;
fi



# We should run on linux
if [ "X${UNAME}" = "XLinux" ]; then
   if [ "x${ACTION}" = "xadd" ]; then
      ARG="-I ${CHAIN} -s ${IP} -j DROP"
   else
      ARG="-D ${CHAIN} -s ${IP} -j DROP"
   fi

   # Checking if iptables is present
   if [ ! -x ${IPTABLES} ]; then
      IPTABLES="/usr"${IPTABLES}
      if [ ! -x ${IPTABLES} ]; then
        echo "$0: can not find iptables"
        exit 0;
      fi
   fi

   # Executing and exiting
   COUNT=0;
   lock;
   ensure_ossec_chain
   while [ 1 ]; do
        ${IPTABLES} ${ARG}
        RES=$?
        if [ $RES = 0 ]; then
            break;
        else
            COUNT=`expr $COUNT + 1`;
            echo "`date` Unable to run (iptables returning != $RES): $COUNT - $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}
            sleep $COUNT;

            if [ $COUNT -gt 4 ]; then
                break;
            fi
        fi
   done
   unlock;

   exit 0;

# FreeBSD, SunOS or NetBSD with ipfilter
elif [ "X${UNAME}" = "XFreeBSD" -o "X${UNAME}" = "XSunOS" -o "X${UNAME}" = "XNetBSD" ]; then

   # Checking if ipfilter is present
   ls ${IPFILTER} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi

   # Checking if echo is present
   ls ${ECHO} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi

   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="\"@1 block out quick from any to ${IP}\""
      ARG2="\"@1 block in quick from ${IP} to any\""
      IPFARG="${IPFILTER} -f -"
   else
      ARG1="\"@1 block out quick from any to ${IP}\""
      ARG2="\"@1 block in quick from ${IP} to any\""
      IPFARG="${IPFILTER} -rf -"
   fi

   # Executing it
   eval ${ECHO} ${ARG1}| ${IPFARG}
   eval ${ECHO} ${ARG2}| ${IPFARG}

   exit 0;

# AIX with ipsec
elif [ "X${UNAME}" = "XAIX" ]; then

  # Checking if genfilt is present
  ls ${GENFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi

  # Checking if lsfilt is present
  ls ${LSFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi
  # Checking if mkfilt is present
  ls ${MKFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi

  # Checking if rmfilt is present
  ls ${RMFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi

  if [ "x${ACTION}" = "xadd" ]; then
    ARG1=" -v 4 -a D -s ${IP} -m 255.255.255.255 -d 0.0.0.0 -M 0.0.0.0 -w B -D \"Access Denied by OSSEC-HIDS\""
    #Add filter to rule table
    eval ${GENFILT} ${ARG1}

    #Deactivate  and activate the filter rules.
    eval ${MKFILT} -v 4 -d
    eval ${MKFILT} -v 4 -u
  else
    # removing a specific rule is not so easy :(
     eval ${LSFILT} -v 4 -O  | ${GREP} ${IP} |
     while read -r LINE
     do
         RULEID=`${ECHO} ${LINE} | cut -f 1 -d "|"`
         let RULEID=${RULEID}+1
         ARG1=" -v 4 -n ${RULEID}"
         eval ${RMFILT} ${ARG1}
     done
    #Deactivate  and activate the filter rules.
    eval ${MKFILT} -v 4 -d
    eval ${MKFILT} -v 4 -u
  fi

else
    exit 0;
fi
