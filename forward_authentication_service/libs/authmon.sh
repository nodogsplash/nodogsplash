#!/bin/sh

url=$1
gatewayhash=$2
phpcli=$3
loopinterval=5
postrequest="/usr/lib/nodogsplash/post-request.php"

#action can be "list" (list and delete from FAS auth log) or "view" (view and leave in FAS auth log)
#
# For debugging purposes, action can be set to "view"
#action="view"
# For normal running, action will be set to "list"
action="list"

version=$(ndsctl status 2>/dev/null | grep Version | awk '{printf $2}')
user_agent="NoDogSplash(authmon;NDS:$version;)"

while true; do
	authlist=$($phpcli -f "$postrequest" "$url" "$action" "$gatewayhash" "$user_agent")

	for clientip in $authlist; do
		echo $clientip
		echo $(ndsctl auth $clientip 2>/dev/null)
	done
	sleep $loopinterval
done

