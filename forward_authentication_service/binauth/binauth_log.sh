#!/bin/sh

# This is an example script for BinAuth
# It can set the session duration per client and writes a local log.
#
# It also retrieves redir, a variable that either contains the originally requested url
# or a url-encoded or aes-encrypted payload of custom variables sent from FAS or PreAuth.
#
# If BinAuth is enabled, NDS will call this script as soon as it has received an authentication request
# from the web page served to the client's CPD (Captive Portal Detection) Browser by one of the following:
#
# 1. splash.html
# 2. PreAuth
# 3. FAS
#

# Get the current Date/Time for the log
date=$(date)

#
# Get the action method from NDS ie the first command line argument.
#
# Possible values are:
# "auth_client" - NDS requests validation of the client
# "client_auth" - NDS has authorised the client
# "client_deauth" - NDS has deauthorised the client
# "idle_deauth" - NDS has deauthorised the client because the idle timeout duration has been exceeded
# "timeout_deauth" - NDS has deauthorised the client because the session length duration has been exceeded
# "ndsctl_auth" - NDS has authorised the client because of an ndsctl command
# "ndsctl_deauth" - NDS has deauthorised the client because of an ndsctl command
# "shutdown_deauth" - NDS has deauthorised the client because it received a shutdown command
#
action=$1

if [ $action == "auth_client" ]; then
	#
	# The redir parameter is sent to this script as the fifth command line argument in url-encoded form.
	#
	# In the case of a simple splash.html login, redir is the URL originally requested by the client CPD.
	#
	# In the case of PreAuth or FAS it MAY contain not only the originally requested URL
	# but also a payload of custom variables defined by Preauth or FAS.
	#
	# It may just be simply url-encoded (fas_secure_enabled 0 and 1), or
	# aes encrypted (fas_secure_enabled 2)
	#
	# The username and password variables may be passed from splash.html, FAS or PreAuth and can be used
	# not just as "username" and "password" but also as general purpose string variables to pass information to BinAuth.

	# Append to the log.
	echo "$date method=$1 clientmac=$2 username=$3 password=$4 redir=$5" >> /tmp/binauth.log
else
	echo "$date method=$1 clientmac=$2 bytes_incoming=$3 bytes_outgoing=$4 session_start=$5 session_end=$6" >> /tmp/binauth.log
fi


# Set length of session in seconds (eg 24 hours is 86400 seconds - if set to 0 then defaults to global sessiontimeout value):
session_length=0
# The session length could be determined by FAS or PreAuth, on a per client basis, and embedded in the redir variable payload.

# Finally before exiting, output the session length, followed by two integers (reserved for future use in traffic shaping)
echo $session_length 0 0

# exit 0 tells NDS is is ok to allow the client to have access.
# exit 1 would tell NDS to deny access.
exit 0
