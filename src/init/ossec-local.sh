#!/bin/sh
# ossec-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Getting where we are installed
LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
PLIST=${DIR}/bin/.process_list;

###  Do not modify below here ###

# Getting additional processes
ls -la ${PLIST} > /dev/null 2>&1
if [ $? = 0 ]; then
. ${PLIST};
fi

NAME="OSSEC HIDS"
VERSION="v4.2.0"
DAEMONS="ossec-monitord ossec-logcollector ossec-syscheckd ossec-analysisd ossec-maild ossec-execd ${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON}"

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="10"

checkpid() {
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

lock() {
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
    echo ""
    echo "Usage: $0 {start|stop|restart|status|enable|disable}";
    exit 1;
}

# Enables additional daemons
enable()
{
    if [ "X$2" = "X" ]; then
        echo ""
        echo "Enable options: database, client-syslog, agentless, debug"
        echo "Usage: $0 enable [database|client-syslog|agentless|debug]"
        exit 1;
    fi

    if [ "X$2" = "Xdatabase" ]; then
        echo "DB_DAEMON=ossec-dbd" >> ${PLIST};
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "CSYSLOG_DAEMON=ossec-csyslogd" >> ${PLIST};
    elif [ "X$2" = "Xagentless" ]; then
        echo "AGENTLESS_DAEMON=ossec-agentlessd" >> ${PLIST};
    elif [ "X$2" = "Xdebug" ]; then
        echo "DEBUG_CLI=\"-d\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid enable option."
        echo ""
        echo "Enable options: database, client-syslog, agentless, debug"
        echo "Usage: $0 enable [database|client-syslog|agentless|debug]"
        exit 1;
    fi
}

# Disables additional daemons
disable()
{
    if [ "X$2" = "X" ]; then
        echo ""
        echo "Disable options: database, client-syslog, agentless, debug"
        echo "Usage: $0 disable [database|client-syslog|agentless,debug]"
        exit 1;
    fi

    if [ "X$2" = "Xdatabase" ]; then
        echo "DB_DAEMON=\"\"" >> ${PLIST};
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "CSYSLOG_DAEMON=\"\"" >> ${PLIST};
    elif [ "X$2" = "Xagentless" ]; then
        echo "AGENTLESS_DAEMON=\"\"" >> ${PLIST};
    elif [ "X$2" = "Xdebug" ]; then
        echo "DEBUG_CLI=\"\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid disable option."
        echo ""
        echo "Disable options: database, client-syslog, agentless, debug"
        echo "Usage: $0 disable [database|client-syslog|agentless|debug]"
        exit 1;
    fi
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
    # We first loop to check the config
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t ${DEBUG_CLI};
        if [ $? != 0 ]; then
            echo "${i}: Configuration error. Exiting"
            unlock;
            exit 1;
        fi
    done
}

start()
{
    SDAEMONS="${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON} ossec-maild ossec-execd ossec-analysisd ossec-logcollector ossec-syscheckd ossec-monitord"

    echo "Starting $NAME $VERSION..."
    echo | ${DIR}/bin/ossec-logtest > /dev/null 2>&1;
    if [ ! $? = 0 ]; then
        echo "ossec-analysisd: Configuration error. Exiting."
        exit 1;
    fi

    lock;
    checkpid;

    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            ${DIR}/bin/${i} ${DEBUG_CLI};
            if [ $? != 0 ]; then
                echo "${i} did not start correctly.";
                unlock;
                exit 1;
            fi
            echo "Started ${i}..."

            if [ X"$i" = "Xossec-analysisd" ]; then
                wait_for_analysis_queue
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

    ls -la "${DIR}/ossec-agent/" >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo ""
        echo "Starting sub agent directory (for hybrid mode)"
        ${DIR}/ossec-agent/bin/ossec-control start
    fi

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

    ls -la "${DIR}/ossec-agent/" >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo ""
        echo "Stopping sub agent directory (for hybrid mode)"
        ${DIR}/ossec-agent/bin/ossec-control stop
    fi
    echo "$NAME $VERSION Stopped"
}

wait_for_analysis_queue()
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
    echo "ERROR: analysis queue not ready at ${qpath} after ${max}s"
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
status)
    status
    ;;
help)
    help
    ;;
enable)
    enable $1 $2;
    ;;
disable)
    disable $1 $2;
    ;;
*)
    help
esac

