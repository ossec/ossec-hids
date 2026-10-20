#!/bin/sh
# Adds an IP to the iptables drop list (if linux)
# Adds an IP to the ipfilter drop list (if solaris, freebsd or netbsd)
# Adds an IP to the ipsec drop list (if aix)
# Requirements: Linux with iptables, Solaris/FreeBSD/NetBSD with ipfilter or AIX with IPSec
# Expect: srcip
# Author: Ahmet Ozturk (ipfilter and IPSec)
# Author: Daniel B. Cid (iptables)
# Author: cgzones
# Last modified: Oct 12, 2026
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

# Bare IPv4 or IPv6. Shell metacharacters are rejected before any command runs.
valid_ipv4()
{
    _v4=$1
    case "${_v4}" in
        .*) return 1;;
        *.) return 1;;
    esac
    _n=0
    _rest4=${_v4}

    while [ -n "${_rest4}" ]; do
        _oct=${_rest4%%.*}
        case "${_rest4}" in
            *.*) _rest4=${_rest4#*.};;
            *) _rest4="";;
        esac
        case "${_oct}" in
            0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
            *) return 1;;
        esac
        _n=`expr ${_n} + 1`
    done

    [ "${_n}" -eq 4 ]
}

valid_ipv6()
{
    _v6=$1
    case "${_v6}" in
        *:::*|*::*::*) return 1;;
        :[!:]*) return 1;;
        *[!:]:) return 1;;
        *::*) _compress=1;;
        *) _compress=0;;
    esac

    _groups=0
    _rest6=${_v6}
    while [ -n "${_rest6}" ]; do
        _grp=${_rest6%%:*}
        case "${_rest6}" in
            *:*) _rest6=${_rest6#*:};;
            *) _rest6="";;
        esac

        if [ -z "${_grp}" ]; then
            if [ "${_compress}" -eq 0 ]; then
                return 1
            fi
            continue
        fi

        case "${_grp}" in
            *.*)
                if [ -n "${_rest6}" ]; then
                    return 1
                fi
                valid_ipv4 "${_grp}" || return 1
                _groups=`expr ${_groups} + 2`
                ;;
            [0-9A-Fa-f]|[0-9A-Fa-f][0-9A-Fa-f]|[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]|[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])
                _groups=`expr ${_groups} + 1`
                ;;
            *)
                return 1
                ;;
        esac
    done

    if [ "${_compress}" -eq 1 ]; then
        [ "${_groups}" -lt 8 ]
    else
        [ "${_groups}" -eq 8 ]
    fi
}

valid_ip()
{
    _ip=$1
    case "${_ip}" in
        ""|*[!0-9A-Fa-f.:]*) return 1;;
    esac

    _len=`expr "${_ip}" : '.*'`
    if [ "${_len}" -gt 45 ]; then
        return 1
    fi

    case "${_ip}" in
        *:*) valid_ipv6 "${_ip}";;
        *) valid_ipv4 "${_ip}";;
    esac
}

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
filename=$(basename "$0")

# Logging the call (ossec-execd sends our stdout/stderr to logs/active-responses.log)
echo "`date` $0 $1 $2 $3 $4 $5"


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>"
   exit 1;
fi

if ! valid_ip "${IP}"; then
    echo "`date` Unable to run active response (invalid IP)."
    exit 1
fi

case "${IP}" in
    *:*) IPTABLES=$IP6TABLES;;
    *) IPTABLES=$IP4TABLES;;
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
                    echo "`date` Killed process ${C_PID} holding lock."
                    kill="true"
                    unlock;
                    i=0;
                    S_PID="";
                    break;
                fi
            done

            if [ "x${kill}" = "xfalse" ]; then
                echo "`date` Unable kill process ${C_PID} holding lock."
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
      ARG="-I"
   else
      ARG="-D"
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
        ${IPTABLES} ${ARG} "${CHAIN}" -s "${IP}" -j DROP
        RES=$?
        if [ $RES = 0 ]; then
            break;
        else
            COUNT=`expr $COUNT + 1`;
            echo "`date` Unable to run (iptables returning != $RES): $COUNT - $0 $1 $2 $3 $4 $5"
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
      IPFARG="${IPFILTER} -f -"
   else
      IPFARG="${IPFILTER} -rf -"
   fi

   # Pass the rule as data. Do not eval it: the address is data, not shell.
   ${ECHO} "@1 block out quick from any to ${IP}" | ${IPFARG}
   ${ECHO} "@1 block in quick from ${IP} to any" | ${IPFARG}

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
    #Add filter to rule table
    ${GENFILT} -v 4 -a D -s "${IP}" -m 255.255.255.255 -d 0.0.0.0 -M 0.0.0.0 -w B -D "Access Denied by OSSEC-HIDS"

    #Deactivate  and activate the filter rules.
    ${MKFILT} -v 4 -d
    ${MKFILT} -v 4 -u
  else
    # removing a specific rule is not so easy :(
     ${LSFILT} -v 4 -O | ${GREP} -F "${IP}" |
     while read -r LINE
     do
         RULEID=`${ECHO} ${LINE} | cut -f 1 -d "|"`
         let RULEID=${RULEID}+1
         ${RMFILT} -v 4 -n "${RULEID}"
     done
    #Deactivate  and activate the filter rules.
    ${MKFILT} -v 4 -d
    ${MKFILT} -v 4 -u
  fi

else
    exit 0;
fi
