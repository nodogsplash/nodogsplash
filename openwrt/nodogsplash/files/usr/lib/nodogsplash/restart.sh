#!/bin/sh

# Check if nodogsplash is running
if ndsctl status &> /dev/null; then
  if [ "$(uci -q get nodogsplash.@nodogsplash[0].fwhook_enabled)" = "1" ]; then
    ndspid=$(ps | grep nodogsplash | awk -F ' ' 'NR==2 {print $1}')
    echo "fwhook restart request received - restarting " | logger -p "daemon.err" -s -t "nodogsplash[$ndspid]: "
    /etc/init.d/nodogsplash restart
  fi
fi
