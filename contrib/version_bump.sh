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
sed -ie "s/VERSION=\"v${OLDVERSION}/VERSION=\"v${NEWVERSION}/" src/init/ossec-client.sh
sed -ie "s/VERSION=\"v${OLDVERSION}/VERSION=\"v${NEWVERSION}/" src/init/ossec-local.sh
sed -ie "s/VERSION=\"v${OLDVERSION}/VERSION=\"v${NEWVERSION}/" src/init/ossec-server.sh

# Win32 files
sed -ie "s/VERSION \"${OLDVERSION}/VERSION \"${NEWVERSION}/" src/win32/ossec-installer.nsi
sed -ie "s/Agent v${OLDVERSION}/Agent v${NEWVERSION}/" src/win32/help.txt

# misc
sed -ie "s/OSSEC v${OLDVERSION}/OSSEC v${NEWVERSION}/" INSTALL
sed -ie "s/OSSEC v${OLDVERSION}/OSSEC v${NEWVERSION}/" README.md

