#!/bin/sh
# Adds an IP to Cloudflare IP block list
# Path: /var/ossec/active-response/bin/cloudflare-ban.sh
# Authors: Bryan Dwyer (bdtech) and Almir Bolduan (almirb)
# Last modified: May 08, 2019
#
# Sample config (Edit /var/ossec/etc/ossec.conf):
#
#  <command>
#     <name>cloudflare-ban</name>
#     <executable>cloudflare-ban.sh</executable>
#     <timeout_allowed>yes</timeout_allowed>
#     <expect>srcip</expect>
#  </command>
#
#  <active-response>
#     <command>cloudflare-ban</command>
#     <location>server</location>
#     <rules_id>31151,31152,31153,31154,31163</rules_id>
#     <timeout>43200</timeout>
#  </active-response>

ACTION=$1
USER=$2
IP=$3
PWD=`pwd`
TOKEN='Cloudflare API Token'
USER='cloudflareuser@email.com'
MODE='block' # block or challenge

# Logging the call (ossec-execd sends our stdout/stderr to logs/active-responses.log)
echo "`date` $0 $1 $2 $3 $4 $5"

# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)"
   exit 1;
fi

# Command line arguments are visible to every local user (ps), so the
# authentication headers go to curl on stdin (-K -) instead of as -H options.

# Adding the ip to null route
if [ "x${ACTION}" = "xadd" ]; then
   curl -sSX POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" \
   -K - \
   -H "Content-Type: application/json" \
   --data "{\"mode\":\"$MODE\",\"configuration\":{\"target\":\"ip\",\"value\":\"$IP\"},\"notes\":\"Added via OSSEC Command\"}" <<EOF
header = "X-Auth-Email: $USER"
header = "X-Auth-Key: $TOKEN"
EOF
   exit 0;


# Deleting from null route
# be carefull not to remove your default route
elif [ "x${ACTION}" = "xdelete" ]; then

   # get the rule ID
   JSON=$(curl -sSX GET "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?mode=$MODE&configuration_target=ip&configuration_value=$IP" \
   -K - \
   -H "Content-Type: application/json" <<EOF
header = "X-Auth-Email: $USER"
header = "X-Auth-Key: $TOKEN"
EOF
   )
   
   ID=$(echo $JSON | jq -r '.result[].id')
    
   curl -sSX DELETE "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/$ID" \
   -K - \
   -H "Content-Type: application/json" <<EOF
header = "X-Auth-Email: $USER"
header = "X-Auth-Key: $TOKEN"
EOF
   exit 0;

# Invalid action
else
   echo "$0: invalid action: ${ACTION}"
fi

exit 1;
