#!/bin/sh


## Run this from src/
## Do not add the "v" before the version number

OLDVERSION=${1}
NEWVERSION=${2}

if [ "X${OLDVERSION}" == "X" ]; then
    echo "You must provide the version numbers"
    echo "version_bump.sh x.0.0 x.1.0"
    exit 1
fi

if [ "X${NEWVERSION}" == "X" ]; then
    echo "You must provide the version numbers"
    echo "version_bump.sh x.0.0 x.1.0"
    exit 1
fi

echo "v${NEWVERSION}" > src/VERSION

# OSSEC init scripts
sed -i -e "s/VERSION=\"v${OLDVERSION}/VERSION=\"v${NEWVERSION}/" src/init/ossec-client.sh
sed -i -e "s/VERSION=\"v${OLDVERSION}/VERSION=\"v${NEWVERSION}/" src/init/ossec-local.sh
sed -i -e "s/VERSION=\"v${OLDVERSION}/VERSION=\"v${NEWVERSION}/" src/init/ossec-server.sh

# Win32 files
sed -i -e "s/VERSION \"${OLDVERSION}/VERSION \"${NEWVERSION}/" src/win32/ossec-installer.nsi
sed -i -e "s/Agent v${OLDVERSION}/Agent v${NEWVERSION}/" src/win32/help.txt

# misc
sed -i -e "s/OSSEC v${OLDVERSION}/OSSEC v${NEWVERSION}/" INSTALL
sed -i -e "s/OSSEC v${OLDVERSION}/OSSEC v${NEWVERSION}/" README.md
sed -i -e "s/OSSEC v${OLDVERSION}/OSSEC v${NEWVERSION}/" CONFIG
sed -i -e "s/OSSEC v${OLDVERSION}/OSSEC v${NEWVERSION}/" BUGS

# update defs.h
sed -i -e "s/v${OLDVERSION}/v${NEWVERSION}/" src/headers/defs.h

# Update CONFIG

