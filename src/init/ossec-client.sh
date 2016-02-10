#!/bin/sh
# ossec-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;


###  Do not modify bellow here ###
NAME="OSSEC HIDS"
VERSION="v2.8.2"
AUTHOR="Trend Micro Inc."
DAEMONS="ossec-logcollector ossec-syscheckd ossec-agentd ossec-execd"

[ -f /etc/ossec-init.conf ] && . /etc/ossec-init.conf

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="10"

checkpid()
{
    for i in ${DAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}*.pid 2>/dev/null`; do
            ps -p $j |grep ossec >/dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "Deleting PID file '${DIR}/var/run/${i}-${j}.pid' not used..."
                rm ${DIR}/var/run/${i}-${j}.pid
            fi
        done
    done
}

lock()
{
    i=0;

    # Providing a lock.
    while [ 1 ]; do
        mkdir ${LOCK} > /dev/null 2>&1
        MSL=$?
        if [ "${MSL}" = "0" ]; then
            # Lock aquired (setting the pid)
            echo "$$" > ${LOCK_PID}
            return;
        fi

        # Waiting 1 second before trying again
        sleep 1;
        i=`expr $i + 1`;

        # If PID is not present, speed things a bit.
        kill -0 `cat ${LOCK_PID}` >/dev/null 2>&1
        if [ ! $? = 0 ]; then
            # Pid is not present.
            i=`expr $i + 1`;
        fi

        # We tried 10 times to acquire the lock.
        if [ "$i" = "${MAX_ITERATION}" ]; then
            # Unlocking and executing
            unlock;
            mkdir ${LOCK} > /dev/null 2>&1
            echo "$$" > ${LOCK_PID}
            return;
        fi
    done
}

unlock()
{
    rm -rf ${LOCK}
}

help()
{
    # Help message
    echo "Usage: $0 {start|stop|restart|status}";
    exit 1;
}

status()
{
    RETVAL=0
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            RETVAL=1
            echo "${i} not running..."
        else
            echo "${i} is running..."
        fi
    done
    exit $RETVAL
}

testconfig()
{
    # We first loop to check the config.
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t;
        if [ $? != 0 ]; then
            echo "${i}: Configuration error. Exiting"
            unlock;
            exit 1;
        fi
    done
}

# Start function
start()
{
    SDAEMONS="ossec-execd ossec-agentd ossec-logcollector ossec-syscheckd"

    echo "Starting $NAME $VERSION (by $AUTHOR)..."
    lock;
    checkpid;

    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            ${DIR}/bin/${i};
            if [ $? != 0 ]; then
                echo "${i} did not start";
                unlock;
                exit 1;
            fi

            echo "Started ${i}..."
        else
            echo "${i} already running..."
        fi
    done

    # After we start we give 2 seconds for the daemons
    # to internally create their PID files.
    sleep 2;
    unlock;
    echo "Completed."
}

pstatus()
{
    pfile=$1;

    # pfile must be set
    if [ "X${pfile}" = "X" ]; then
        return 0;
    fi

    ls ${DIR}/var/run/${pfile}*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        for j in `cat ${DIR}/var/run/${pfile}*.pid 2>/dev/null`; do
            ps -p $j |grep ossec >/dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "${pfile}: Process $j not used by ossec, removing .."
                rm -f ${DIR}/var/run/${pfile}-$j.pid
                continue;
            fi

            kill -0 $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                return 1;
            fi
        done
    fi

    return 0;
}

stopa()
{
    lock;
    checkpid;
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            echo "Killing ${i} .. ";

            kill `cat ${DIR}/var/run/${i}*.pid`;
        else
            echo "${i} not running ..";
        fi

        rm -f ${DIR}/var/run/${i}*.pid
     done

    unlock;
    echo "$NAME $VERSION Stopped"
}

### MAIN HERE ###

case "$1" in
start)
    testconfig
    start
    ;;
stop)
    stopa
    ;;
restart)
    testconfig
    stopa
    sleep 1;
    start
    ;;
reload)
    DAEMONS="ossec-logcollector ossec-syscheckd ossec-agentd"
    stopa
    start
    ;;
status)
    status
    ;;
help)
    help
    ;;
*)
    help
esac

