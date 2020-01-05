#!/bin/sh
#Copyright (C) The Nodogsplash Contributors 2004-2020
#Copyright (C) BlueWave Projects and Services 2015-2020
#This software is released under the GNU GPL license.

# This is an example script for BinAuth
# It verifies a client username and password and sets the session length.
#
# If BinAuth is enabled, NDS will call this script as soon as it has received an authentication request
# from the web page served to the client's CPD (Captive Portal Detection) Browser by one of the following:
#
# 1. splash_sitewide.html
# 2. PreAuth
# 3. FAS
#
# The username and password entered by the clent user will be included in the query string sent to NDS via html GET
# For an example, see the file splash_sitewide.html

METHOD="$1"
CLIENTMAC="$2"

case "$METHOD" in
	auth_client)
		USERNAME="$3"
		PASSWORD="$4"
		REDIR="$5"
		USER_AGENT="$6"
		CLIENTIP="$7"

		if [ "$USERNAME" = "Staff" -a "$PASSWORD" = "weneedit" ]; then
			# Allow Staff to access the Internet for the global sessiontimeout interval
			# Further values are reserved for upload and download limits in bytes. 0 for no limit.
			echo 0 0 0
			exit 0
		elif [ "$USERNAME" = "Guest" -a "$PASSWORD" = "thanks" ]; then
			# Allow Guest to access the Internet for 10 minutes (600 seconds)
			# Further values are reserved for upload and download limits in bytes. 0 for no limit.
			echo 600 0 0
			exit 0
		else 
			# Deny client access to the Internet.
			exit 1
		fi

		;;
	client_auth|client_deauth|idle_deauth|timeout_deauth|ndsctl_auth|ndsctl_deauth|shutdown_deauth)
		INGOING_BYTES="$3"
		OUTGOING_BYTES="$4"
		SESSION_START="$5"
		SESSION_END="$6"
		# client_auth: Client authenticated via this script.
		# client_deauth: Client deauthenticated by the client via splash page.
		# idle_deauth: Client was deauthenticated because of inactivity.
		# timeout_deauth: Client was deauthenticated because the session timed out.
		# ndsctl_auth: Client was authenticated by the ndsctl tool.
		# ndsctl_deauth: Client was deauthenticated by the ndsctl tool.
		# shutdown_deauth: Client was deauthenticated by Nodogsplash terminating.
		;;
esac

