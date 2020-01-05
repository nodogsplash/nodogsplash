#!/bin/sh

# Check if nodogsplash is running
ndspid=$(ps | grep nodogsplash_cfg | awk -F ' ' 'NR==2 {print $1}')
if [ ! -z $ndspid ]; then
  if [ "$(uci -q get nodogsplash.@nodogsplash[0].fwhook_enabled)" = "1" ]; then
    echo "fwhook restart request received - restarting " | logger -p "daemon.warn" -s -t "nodogsplash[$ndspid]: "
    /etc/init.d/nodogsplash restart
  fi
fi
