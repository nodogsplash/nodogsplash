#!/bin/sh
#Copyright (C) Blue Wave Projects and Services 2015-2019
#This software is released under the GNU GPL license.

# This script requires the iw package (usually available by default)

# mac address of client is passed as a command line argument
mac=$1

# exit if mac not passed
if [ -z $mac ]; then
	exit 1
fi

# Get default interface
# This will be the interface NDS is bound to eg. br-lan
clientif=$(ip -4 neigh | awk -F ' ' 'match($s,"'"$mac"' REACHABLE")>0 {printf $3" "}')

if [ -z $clientif ]; then
	# The client has gone offline eg battery saving or switched to another ssid
	exit 1
fi

# Get list of wireless interfaces on this device
# This list will contain all the wireless interfaces configured on the device
# eg wlan0, wlan0-1, wlan1, wlan1-1 etc
interface_list=$(iw dev | awk -F 'Interface ' 'NF>1{printf $2" "}')

# Scan the wireless interfaces on this device for the client mac
for interface in $interface_list; do
	macscan=$(iw dev $interface station dump | awk -F " " 'match($s, "'"$mac"'")>0{print $2}')
	if [ ! -z $macscan ]; then
		clientif=$interface
		break
	fi
done

# Return the local interface the client is using
echo $clientif

exit 0

