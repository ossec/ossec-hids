#!/bin/sh
# ossec-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;


###  Do not modify below here ###
NAME="OSSEC HIDS"
VERSION="v4.2.0"
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
            # Lock acquired (setting the pid)
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
    echo "Usage: $0 {start|stop|reload|restart|status}";
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

    echo "Starting $NAME $VERSION..."
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

            # Agent queue owner is ossec-agentd (local producers connect to it).
            if [ X"$i" = "Xossec-agentd" ]; then
                wait_for_agent_queue
                if [ $? != 0 ]; then
                    unlock;
                    exit 1;
                fi
            fi
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

wait_pids_gone()
{
    local grace=45
    local elapsed=0
    local pid
    local still

    if [ "X$*" = "X" ]; then
        return 0
    fi

    while [ ${elapsed} -lt ${grace} ]; do
        still=0
        for pid in $*; do
            kill -0 ${pid} >/dev/null 2>&1
            if [ $? = 0 ]; then
                still=1
                break
            fi
        done
        if [ ${still} = 0 ]; then
            return 0
        fi
        sleep 1
        elapsed=`expr ${elapsed} + 1`
    done

    for pid in $*; do
        kill -0 ${pid} >/dev/null 2>&1
        if [ $? = 0 ]; then
            echo "Process ${pid} did not exit; sending SIGKILL .."
            kill -9 ${pid} >/dev/null 2>&1
        fi
    done
    sleep 1
}

stopa()
{
    lock;
    checkpid;
    WAIT_PIDS=""
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            echo "Killing ${i} .. ";
            for j in `cat ${DIR}/var/run/${i}*.pid 2>/dev/null`; do
                kill ${j} >/dev/null 2>&1
                WAIT_PIDS="${WAIT_PIDS} ${j}"
            done
        else
            echo "${i} not running ..";
        fi

        rm -f ${DIR}/var/run/${i}*.pid
     done

    wait_pids_gone ${WAIT_PIDS}

    rm -f ${DIR}/queue/ossec/queue 2>/dev/null

    unlock;
    echo "$NAME $VERSION Stopped"
}

wait_for_agent_queue()
{
    local elapsed=0
    local max=60
    local qpath="${DIR}/queue/ossec/queue"

    while [ ${elapsed} -lt ${max} ]; do
        if [ -S "${qpath}" ] || [ -e "${qpath}" ]; then
            python3 - "${qpath}" <<'PY' 2>/dev/null
import socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
    s.connect(path)
except Exception:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
            if [ $? = 0 ]; then
                return 0
            fi
        fi
        sleep 1
        elapsed=`expr ${elapsed} + 1`
    done
    echo "ERROR: agent queue not ready at ${qpath} after ${max}s"
    return 1
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

