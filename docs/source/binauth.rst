BinAuth Option
=================

Overview
********

**BinAuth provides a method of running a post authentication script** or extension program. BinAuth is ALWAYS local to NDS and as such will have access to all the resources of the local system.

**BinAuth works with, but does not require FAS** and in a simple system can be used to provide site-wide username/password access.

**With FAS, the redir variable forwarded to BinAuth** can contain an embedded payload of custom variables defined by the FAS. As FAS is typically remote from the NDS router, this provides a link to the local system.

**BinAuth has the means to set a session timeout** interval on a client by client basis.

**BinAuth is called by NDS at the following times:**

 * After the client CPD browser makes an authentication request to NDS
 * After the client device is granted Internet access by NDS
 * After the client is deauthenticated by request
 * After the client idle timeout interval has expired
 * After the client session timeout interval has expired
 * After the client is authenticated by ndsctl command
 * After the client is deauthenticated by ndsctl command
 * After NDS has received a shutdown command

Example BinAuth Scripts
***********************
Two example BinAuth scripts are included in the source files available for download at:
https://github.com/nodogsplash/nodogsplash/releases

The files can be extracted from the downloaded release archive file and reside in the folder:

`/nodogsplash-[*version*]/forward_authentication_service/binauth`

Example 1 - Sitewide Username/Password
**************************************
This example is a script designed to be used with or without FAS and provides site wide Username/Password login for two groups of users, in this case "Staff" and "Guest" with two corresponding sets of credentials. If used without FAS, a special html splash page must be installed, otherwise FAS must forward the required username and password variables.

The "Staff" user is allowed access to the Internet for the full duration of the global sessiontimeout interval before being logged out.

The "Guest" user is allowed access for 10 minutes before being logged out.

Installing Example 1
********************
This script has two components, the actual script and an associated html file.

 * binauth_sitewide.sh
 * splash_sitewide.html

The file binauth_sitewide.sh should be copied to a suitable location on the NDS router, eg `/etc/nodogsplash/`

The file splash_sitewide.html should be copied to `/etc/nodogsplash/htdocs/`

Assuming FAS is not being used, NDS is then configured by setting the BinAuth and SplashPage options in the config file (/etc/config/nodogsplash on Openwrt, or /etc/nodogsplash/nodogsplash.conf on other operating systems.

On OpenWrt this is most easily accomplished by issuing the following commands:

    `uci set nodogsplash.@nodogsplash[0].splashpage='splash_sitewide.html'`

    `uci set nodogsplash.@nodogsplash[0].binauth='/etc/nodogsplash/binauth_sitewide.sh'`

    `uci commit nodogsplash`

The script file must be executable and is flagged as such in the source archive. If necessary set using the command:

    `chmod u+x /etc/nodogsplash/binauth_sitewide.sh`

This script is then activated with the command:

    `service nodogsplash restart`

**The Example 1 script contains the following code:**

.. code-block:: sh

 #!/bin/sh

 # EXAMPLE 1
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


The `SESSION_START` and `SESSION_END` values are the number of seconds since 1970 or may be 0 for unknown/unlimited.

**The splash_sitewide.html page contains the following code:**

.. code-block:: html

 <!DOCTYPE html>
 <html>
 <head>
 <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
 <meta http-equiv="Pragma" content="no-cache">
 <meta http-equiv="Expires" content="0">
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">

 <link rel="shortcut icon" href="/images/splash.jpg" type="image/x-icon">
 <link rel="stylesheet" type="text/css" href="/splash.css">

 <title>$gatewayname Captive Portal.</title>

 <!--
 Content:
	Nodogsplash (NDS), by default, serves this splash page (splash.html)
	when a client device Captive Portal Detection (CPD) process
	attempts to send a port 80 request to the Internet.

	You may either embed css in this file or use a separate .css file
	in the same directory as this file, as demonstrated here.

	It should be noted when designing a custom splash page
	that for security reasons many CPD implementations:
		Immediately close the browser when the client has authenticated.
		Prohibit the use of href links.
		Prohibit downloading of external files
			(including .css and .js).
		Prohibit the execution of javascript.

 Authentication:
	A client is authenticated on submitting an HTTP form, method=get,
	passing $authaction, $tok and $redir.

	It is also possible to authenticate using an href link to
	$authtarget but be aware that many device Captive Portal Detection
	processes prohibit href links, so this method may not work with
	all client devices.

 Available variables:
	error_msg: $error_msg
	gatewayname: $gatewayname
	tok: $tok
	redir: $redir
	authaction: $authaction
	denyaction: $denyaction
	authtarget: $authtarget
	clientip: $clientip
	clientmac: $clientmac
	clientupload: $clientupload
	clientdownload: $clientdownload
	gatewaymac: $gatewaymac
	nclients: $nclients
	maxclients: $maxclients
	uptime: $uptime

 Additional Variables that can be passed back via the HTTP get,
 or appended to the query string of the authtarget link:
	username
	password
 -->

 </head>

 <body>
 <div class="offset">
 <med-blue>$gatewayname Captive Portal.</med-blue>
 <div class="insert">
 <img style="height:60px; width:60px; float:left;" src="/images/splash.jpg" alt="Splash Page: For access to the Internet.">
 <big-red>Welcome!</big-red>
 <hr>
 <br>
 <italic-black>For access to the Internet, please enter your Username and Password.</italic-black>
 <br><br>
 <hr>

 <form method="get" action="$authaction">
 <input type="hidden" name="tok" value="$tok">
 <input type="hidden" name="redir" value="$redir">
 <input type="text" placeholder="Enter Username" name="username" value="" size="12" maxlength="12">
 <br>Username<br><br>
 <input type="password" placeholder="Enter Password" name="password" value="" size="12" maxlength="10">
 <br>Password<br><br>
 <input type="submit" value="Continue">
 </form>

 <hr>
 <copy-right>Copyright &copy; The Nodogsplash Contributors 2004-2019.<br>This software is released under the GNU GPL license.</copy-right>

 </div></div>
 </body>
 </html>

Example 2 - Local NDS Access Log
********************************

This example is a script designed to be used with or without FAS and provides local NDS logging. FAS is often remote from the NDS router and this script provides a simple method of interacting directly with the local NDS. FAS can provide the values of custom variables securly embedded as a payload in the redir parameter that is relayed to BinAuth by NDS. FAS can also utilise the username and password parameters to send general purpose variables although these will be readable by the client user on their browser screen.

The log file is stored by default in the /tmp/ directory but no free space checking is done in this simple example.
It would be a simple matter to change the location of the log file to a USB stick for example.

Installing Example 2
********************
This script has a single component, the shell script.

 * binauth_log.sh

The file binauth_log.sh should be copied to a suitable location on the NDS router, eg `/etc/nodogsplash/`

Assuming FAS is not being used, NDS is then configured by setting the BinAuth option in the config file (/etc/config/nodogsplash on Openwrt, or /etc/nodogsplash/nodogsplash.conf on other operating systems.

On OpenWrt this is most easily accomplished by issuing the following commands:

    `uci set nodogsplash.@nodogsplash[0].binauth='/etc/nodogsplash/binauth_log.sh'`

    `uci commit nodogsplash`

The script file must be executable and is flagged as such in the source archive. If necessary set using the command:

    `chmod u+x /etc/nodogsplash/binauth_log.sh`

This script is then activated with the command:

    `service nodogsplash restart`

**The Example 2 script contains the following code:**

.. code-block:: sh

 #!/bin/sh

 # This is an example script for BinAuth
 # It can set the session duration per client and writes a local log.
 #
 # It retrieves redir, a variable that either contains the originally requested url
 # or a url-encoded or aes-encrypted payload of custom variables sent from FAS or PreAuth.
 #
 # The client User Agent string is also forwarded to this script.
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
	#
	# The client User Agent string is sent as the sixth command line argument.
	# This can be used to determine much information about the capabilities of the client.
	# In this case it will be added to the log.
	#
	# Both redir and useragent are url-encoded, so decode:
	redir_enc=$5
	redir=$(printf "${redir_enc//%/\\x}")
	useragent_enc=$6
	useragent=$(printf "${useragent_enc//%/\\x}")

	# Append to the log.

	echo "$date, method=$1, clientmac=$2, clientip=$7, username=$3, password=$4, redir=$redir, useragent=$useragent" >> /tmp/binauth.log
 else
	echo "$date, method=$1, clientmac=$2, bytes_incoming=$3, bytes_outgoing=$4, session_start=$5, session_end=$6" >> /tmp/binauth.log
 fi


 # Set length of session in seconds (eg 24 hours is 86400 seconds - if set to 0 then defaults to global sessiontimeout value):
 session_length=0
 # The session length could be determined by FAS or PreAuth, on a per client basis, and embedded in the redir variable payload.

 # Finally before exiting, output the session length, followed by two integers (reserved for future use in traffic shaping)
 
 echo $session_length 0 0

 # exit 0 tells NDS is is ok to allow the client to have access.
 # exit 1 would tell NDS to deny access.
 
 exit 0
