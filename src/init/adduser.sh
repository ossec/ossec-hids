#!/bin/sh

set -e
set -u

if ! [ $# -eq 5 ]; then
    echo "Usage: ${0} USERNAME_DEFAULT USERNAME_MAIL USERNAME_REMOTE GROUPNAME DIRECTORY.";
    exit 1;
fi

echo "Wait for success..."

USER=$1
USER_MAIL=$2
USER_REM=$3
GROUP=$4
DIR=$5

UNAME=$(uname);

# Thanks Chuck L. for the mac addusers
if [ "$UNAME" = "Darwin" ]; then
    if ! id -u "${USER}" > /dev/null 2>&1; then

        # Creating for <= 10.4
        if /usr/bin/sw_vers 2>/dev/null| grep "ProductVersion" | grep -E "10.2.|10.3|10.4" > /dev/null 2>&1; then
            chmod +x ./init/darwin-addusers.pl
            ./init/darwin-addusers.pl
        else
            chmod +x ./init/osx105-addusers.sh
            ./init/osx105-addusers.sh
        fi
    fi

else
    if [ "$UNAME" = "FreeBSD" -o "$UNAME" = "DragonFly" ]; then
        GROUPADD="/usr/sbin/pw groupadd"
        USERADD="/usr/sbin/pw useradd"
        OSMYSHELL="/sbin/nologin"
    elif [ "$UNAME" = "SunOS" ]; then
        GROUPADD="/usr/sbin/groupadd"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/bin/false"
    elif [ "$UNAME" = "AIX" ]; then
        GROUPADD="/usr/sbin/mkgroup"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/bin/false"
    elif [ "$UNAME" = "OpenBSD" ]; then
        GROUPADD="/usr/sbin/groupadd"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/sbin/nologin"
    else
	    # All current linux distributions should support system accounts for
	    # users/groups. If not, leave the GROUPADD/USERADD as it was before
	    # this change
	    sys_acct_chk () {
	        $1 --help 2>&1 | grep -e " *-r.*system account" >/dev/null 2>&1 && echo "$1 -r" || echo "$1"
	    }
	    GROUPADD=$(sys_acct_chk "/usr/sbin/groupadd -f")
	    USERADD=$(sys_acct_chk "/usr/sbin/useradd")
        OSMYSHELL="/sbin/nologin"
    fi

    if [ -x /usr/bin/getent ]; then
        if [ `getent group ossec | wc -l` -lt 1 ]; then
            ${GROUPADD} "${GROUP}"
        fi
    elif ! grep "^${GROUP}" /etc/group > /dev/null 2>&1; then
        ${GROUPADD} "${GROUP}"
    fi

    if [ "${OSMYSHELL}" = "/sbin/nologin" ]; then
        # We first check if /sbin/nologin is present. If it is not,
        # we look for /bin/false. If none of them is present, we
        # just stick with nologin (no need to fail the install for that).
        if [ ! -f ${OSMYSHELL} ]; then
            if [ -f /bin/false ]; then
                OSMYSHELL="/bin/false"
            fi
        fi
    fi

    for U in ${USER} ${USER_MAIL} ${USER_REM}; do
        if [ -x /usr/bin/getent ]; then 
            if [ `getent passwd ${U} | wc -l` -lt 1 ]; then
	            if [ "$UNAME" = "OpenBSD" ] || [ "$UNAME" = "SunOS" ] || [ "$UNAME" = "AIX" ]; then
                    ${USERADD} -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${U}"
	            else
	                ${USERADD} "${U}" -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}"
	            fi
            fi
        elif [ ! `grep "^${U}" /etc/passwd > /dev/null 2>&1` ]; then
	        if [ "$UNAME" = "OpenBSD" ] || [ "$UNAME" = "SunOS" ]; then
                ${USERADD} -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${U}"
	        else
	            ${USERADD} "${U}" -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}"
	        fi
        fi
    done
fi

echo "success";
exit 0;
