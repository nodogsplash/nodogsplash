#!/bin/sh
#Copyright (C) The Nodogsplash Contributors 2004-2020
#Copyright (C) Blue Wave Projects and Services 2015-2020
#This software is released under the GNU GPL license.

option="$1"
inputstr="$2"

if [ "$option" == "-url" ]; then
	printf "${inputstr//%/\\x}"
else
	echo "Invalid option"
	exit 1
fi
