#!/bin/bash

set -e -o pipefail

scriptpath=$(dirname $0)
$scriptpath/contrib/debian-packages/generate_ossec.sh -d
$scriptpath/contrib/debian-packages/generate_ossec.sh -u
$scriptpath/contrib/debian-packages/generate_ossec.sh -b
