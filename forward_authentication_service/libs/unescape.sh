#!/bin/sh
#Copyright (C) The Nodogsplash Contributors 2004-2020
#Copyright (C) BlueWave Projects and Services 2015-2020
#This software is released under the GNU GPL license.
#
# Warning - shebang sh is for compatibliity with busybox ash (eg on OpenWrt)
# This is changed to bash automatically by Makefile for Debian
#

option="$1"
inputstr="$2"
usage="
  Usage: unescape.sh [-option] [escapedstring]

  Returns: [unescapedstring]

  Where:
    [-option] is unescape type, currently -url only
"

if [ "$option" = "-url" ]; then
	printf "${inputstr//%/\\x}"
	exit 0
fi

if [ "$option" = "" ] || [ "$option" = "-h" ] || [ "$option" = "-help" ]; then
	echo "$usage"
	exit 0
else
	echo "Invalid option"
	exit 1
fi
