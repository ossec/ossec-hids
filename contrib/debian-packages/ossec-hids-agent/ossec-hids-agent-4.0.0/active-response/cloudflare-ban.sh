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

# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> /var/ossec/logs/active-responses.log

# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)"
   exit 1;
fi

# Adding the ip to null route
if [ "x${ACTION}" = "xadd" ]; then
   curl -sSX POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" \
   -H "X-Auth-Email: $USER" \
   -H "X-Auth-Key: $TOKEN" \
   -H "Content-Type: application/json" \
   --data "{\"mode\":\"$MODE\",\"configuration\":{\"target\":\"ip\",\"value\":\"$IP\"},\"notes\":\"Added via OSSEC Command\"}"
   exit 0;


# Deleting from null route
# be carefull not to remove your default route
elif [ "x${ACTION}" = "xdelete" ]; then

   # get the rule ID
   JSON=$(curl -sSX GET "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?mode=$MODE&configuration_target=ip&configuration_value=$IP" \
   -H "X-Auth-Email: $USER" \
   -H "X-Auth-Key: $TOKEN" \
   -H "Content-Type: application/json")
   
   ID=$(echo $JSON | jq -r '.result[].id')
    
   curl -sSX DELETE "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/$ID" \
   -H "X-Auth-Email: $USER" \
   -H "X-Auth-Key: $TOKEN" \
   -H "Content-Type: application/json"
   exit 0;

# Invalid action
else
   echo "$0: invalid action: ${ACTION}"
fi

exit 1;
