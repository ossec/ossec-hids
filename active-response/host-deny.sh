#!/bin/sh
# Adds an IP to the /etc/hosts.deny file
# Requirements: sshd and other binaries with tcp wrappers support
# Expect: srcip
# Author: Daniel B. Cid
# Last modified: Nov 09, 2005

ACTION=$1
USER=$2
IP=$3
ALERTID=$4

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
LOCK="${PWD}/host-deny-lock"
LOCK_PID="${PWD}/host-deny-lock/pid"
# Entries written by "add" and not taken back yet ("<ip> <alert id>")
ADDED="${PWD}/host-deny-added"
UNAME=`uname`
HOSTS_DENY="/etc/hosts.deny"
HOSTS_ALLOW="/etc/hosts.allow"


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
            echo "`date` Unable to execute. Locked: $0" \
                        >> ${PWD}/ossec-hids-responses.log

            # Unlocking and exiting
            unlock;
            exit 1;
        fi
    done
}

# Unlock function
unlock()
{
    rm -rf ${LOCK}
}


# Logging the call (ossec-execd sends our stdout/stderr to logs/active-responses.log)
echo "`date` $0 $1 $2 $3 $4 $5"


# IP Address must be provided
if [ "x${IP}" = "x" ]; then
    echo "$0: Missing argument <action> <user> (ip)"
    exit 1;
fi


# Hostname or address. Reject shell metacharacters and values with no "." or ":".
case "${IP}" in
    ""|-*|*[!A-Za-z0-9.:_-]*)
        echo "`date` Invalid ip/hostname entry."
        exit 1
        ;;
    *[.:]*)
        ;;
    *)
        echo "`date` Invalid ip/hostname entry."
        exit 1
        ;;
esac


# Adding the ip to hosts.deny
if [ "x${ACTION}" = "xadd" ]; then
    # Remember the raw address for the add/delete record (before IPv6 brackets)
    RAW_IP="${IP}"
    # IPv6 entries are written in brackets
    echo "${IP}" | grep "\:" > /dev/null 2>&1
    if [ $? = 0 ]; then
        IP="[${IP}]"
    fi
    # Looking for duplication (the exact entry written below, not a pattern)
    if [ "X$UNAME" = "XFreeBSD" ]; then
        IPKEY=$(grep -F -x "ALL : ${IP} : deny" ${HOSTS_ALLOW})
    else
        IPKEY=$(grep -F -x "ALL:${IP}" ${HOSTS_DENY})
    fi
    if [ ! -z "$IPKEY" ]; then
        echo "IP ${IP} already exists on host.deny..."
        exit 1
    fi
    lock;
    # Remembering the entry: "delete" only takes back what "add" wrote
    printf '%s %s\n' "${RAW_IP}" "${ALERTID}" >> ${ADDED}
    if [ "X$UNAME" = "XFreeBSD" ]; then
        echo "ALL : ${IP} : deny" >> ${HOSTS_ALLOW}
    else
        echo "ALL:${IP}" >> ${HOSTS_DENY}
    fi
    unlock;
    exit 0;


# Deleting from hosts.deny
elif [ "x${ACTION}" = "xdelete" ]; then
    lock;
    # ossec-execd runs "delete" even if "add" found the entry already there
    # (the administrator's, or another response's): only taking back what
    # the "add" of the same alert wrote
    grep -F -x -e "${IP} ${ALERTID}" ${ADDED} > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "IP ${IP} was not added by this alert, leaving it..."
        unlock;
        exit 0;
    fi
    TMP_FILE=`mktemp ${PWD}/ossec-hosts.XXXXXXXXXX`
    if [ "X${TMP_FILE}" = "X" ]; then
        # Cheap fake tmpfile, but should be harder then no random data
        TMP_FILE="${PWD}/ossec-hosts.`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -1 `"
    fi
    grep -v -F -x -e "${IP} ${ALERTID}" ${ADDED} > ${TMP_FILE}
    cat ${TMP_FILE} > ${ADDED}
    echo "${IP}" | grep "\:" > /dev/null 2>&1
    if [ $? = 0 ]; then
        IP="[${IP}]"
    fi
    if [ "X$UNAME" = "XFreeBSD" ]; then
        cat ${HOSTS_ALLOW} | grep -F -x -v "ALL : ${IP} : deny"> ${TMP_FILE}
        mv ${TMP_FILE} ${HOSTS_ALLOW}
    else
        cat ${HOSTS_DENY} | grep -F -x -v "ALL:${IP}"> ${TMP_FILE}
        cat ${TMP_FILE} > ${HOSTS_DENY}
        rm ${TMP_FILE}
    fi
    unlock;
    exit 0;


# Invalid action
else
    echo "$0: invalid action: ${ACTION}"
fi

exit 1;
