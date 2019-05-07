#!/bin/sh

hostname=`hostname`
hostname melancia

cleanup() {
    hostname $hostname
    rm -f ./tmpres
}

trap "cleanup" INT TERM EXIT
exitcode=0

if diff --help 2>&1 | grep -q -- --color; then
    diff_cmd='diff --color'
else
    diff_cmd='diff'
fi

echo "Starting log unit tests (must be run as root and on a system with OSSEC installed)."
echo "(it will make sure the current rules are working as they should)."
rm -f ./tmpres
for i in ./*/log; do
    idir=`dirname $i`

    rm -f ./tmpres || exit "Unable to remove tmpres.";
    cat $i | /var/ossec/bin/ossec-logtest 2>&1|grep -av ossec-testrule |grep -aA 500 "Phase 1:" > ./tmpres

    if [ ! -f $idir/res ]; then
        echo "** Creating entry for $i - Not set yet."
        cat ./tmpres > $idir/res
        rm -f tmpres
        continue;
    fi
    MD1=`md5sum ./tmpres | cut -d " " -f 1`
    MD2=`md5sum $idir/res | cut -d " " -f 1`

    if [ ! $MD1 = $MD2 ]; then
        exitcode=1
        echo
        echo
        echo
        echo "**ERROR: Unit testing failed. Output for the test $i failed."
        echo "== DIFF OUTPUT: =="
        $diff_cmd -Na -U `wc -l $idir/res` tmpres
        rm -f tmpres
    fi

done

echo ""
if [ $exitcode -eq 0 ]; then
    echo "Log unit tests completed. Everything seems ok (nothing changed since last test regarding the outputs)."
else
    echo "Log unit tests completed. Some tests failed."
fi
exit $exitcode
