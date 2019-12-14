#!/bin/sh
#Copyright (C) The Nodogsplash Contributors 2004-2019
#Copyright (C) Blue Wave Projects and Services 2015-2019
#This software is released under the GNU GPL license.

# functions:

write_log () {
	logfile="/tmp/ndslog.log"
	min_freespace_to_log_ratio=10
	datetime=$(date)

	if [ ! -f $logfile ]; then
		echo "$datetime, New log file created" > $logfile
	fi

	ndspid=$(ps | grep nodogsplash | awk -F ' ' 'NR==2 {print $1}')
	filesize=$(ls -s -1 $logfile | awk -F' ' '{print $1}')
	available=$(df |grep /tmp | awk -F ' ' '{print $4}')
	sizeratio=$(($available/$filesize))

	if [ $sizeratio -ge $min_freespace_to_log_ratio ]; then
		echo "$datetime, Username=$username, Email Address=$emailaddr, mac address=$clientmac, user_agent=$user_agent" \
			>> $logfile
	else
		echo "PreAuth - log file too big, please archive contents" | logger -p "daemon.err" -s -t "nodogsplash[$ndspid]: "
	fi
}

# Get the urlencoded querystring and user_agent
query_enc="$1"
user_agent_enc="$2"

# The query string is sent to us from NDS in a urlencoded form,
# we can decode it or parts of it using something like the following:
# query=$(printf "${query_enc//%/\\x}")

# The User Agent string is sent urlencoded also:
user_agent=$(printf "${user_agent_enc//%/\\x}")

# In this example script we want to ask the client user for
# their username and email address.
#
# We could ask for anything we like and add our own variables to the html forms
# we generate.
#
# If we want to show a sequence of forms or information pages we can do this easily.
#
# To return to this script and show additional pages, the form action must be set to:
#	<form action=\"/nodogsplash_preauth/\" method=\"get\">
# Note: quotes ( " ) must be escaped with the "\" character.
#
# Any variables we need to preserve and pass back to ourselves or NDS must be added 
# to the form as hidden:
#	<input type=\"hidden\" name=......
# Such variables will appear in the query string when NDS re-calls this script.
# We can then parse for them again.
#
# When the logic of this script decides we should allow the client to access the Internet
# we inform NDS with a final page displaying a continue button with the form action set to:
#	"<form action=\"/nodogsplash_auth/\" method=\"get\">"
#
# We must also send NDS the client token as a hidden variable, but first we must obtain
# the token from ndsctl using a suitable command such as:
#	tok="$(ndsctl json $clientip | grep token | cut -c 10- | cut -c -8)"
#
# In a similar manner we can obtain any client or NDS information that ndsctl provides. 

# The query string NDS sends to us will always be of the following form (with a "comma space" separator):
# ?clientip=[clientipaddress], gatewayname=[gatewayname], redir=[originalurl], var4=[data], var5=[data], var6......
#
# The first three variables will be clientip, gatewayname and redir
#
# We have chosen to name redir as $requested here as it is actually the originally requested url.
#
# There is one exception to this. If the client presses "back" on their browser NDS detects this
# and tells us by returning status=authenticated instead of redir=[originalurl]
# If we detect this we show a page telling the client they are already logged in.
#
# Additional variables returned by NDS will be those we define here and send to NDS via an
# html form method=get
# See the examples here for $username and $emailaddress
#
# There is no limit to the number of variables we can define dynamically
# as long as the query string does not exceed 2048 bytes.
#
# The query string will be truncated if it does exceed this length.


# Parse for the variables returned by NDS:
queryvarlist="clientip gatewayname hid redir status username emailaddr"

for var in $queryvarlist; do
	nextvar=$(echo $queryvarlist | awk '{for(i=1;i<=NF;i++) if ($i=="'$var'") printf $(i+1)}')
	eval $var=$(echo "$query_enc" | awk -F "$var%3d" '{print $2}' | awk -F "%2c%20$nextvar%3d" '{print $1}')
done

# URL decode vars that need it:
requested=$(printf "${redir//%/\\x}")
gatewayname=$(printf "${gatewayname//%/\\x}")
username=$(printf "${username//%/\\x}")
emailaddr=$(printf "${emailaddr//%/\\x}")

# Define some common html as the first part of the page to be served by NDS
#
# Note this example uses the default splash.css provided by NDS and uses splash.jpg
# as the browser shortcut icon.
#
# You can decide how your PreAuth splash page will look
# by incorporating your own css and images.
#
# Note however that the output of this script will be displayed on the client device screen via the CPD process on that device.
# It should be noted when designing a custom splash page that for security reasons many client device CPD implementations:
#
#	Immediately close the browser when the client has authenticated.
#	Prohibit the use of href links.
#	Prohibit downloading of external files (including .css and .js, even if they are allowed in NDS firewall settings).
#	Prohibit the execution of javascript.
#



header="
	<!DOCTYPE html>
	<html>
	<head>
	<meta http-equiv=\"Cache-Control\" content=\"no-cache, no-store, must-revalidate\">
	<meta http-equiv=\"Pragma\" content=\"no-cache\">
	<meta http-equiv=\"Expires\" content=\"0\">
	<meta charset=\"utf-8\">
	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
	<link rel=\"shortcut icon\" href=\"/images/splash.jpg\" type=\"image/x-icon\">
	<link rel=\"stylesheet\" type=\"text/css\" href=\"/splash.css\">
	<title>$gatewayname.</title>
	</head>
	<body>
	<div class=\"offset\">
	<med-blue>$gatewayname.</med-blue>
	<div class=\"insert\" style=\"max-width:100%;\">
	<hr>
"

# Define a common footer for every page served
version="$(ndsctl status | grep Version)"
year="$(date | awk -F ' ' '{print $(6)}')"
footer="
	<img style=\"height:60px; width:60px; float:left;\" src=\"/images/splash.jpg\" alt=\"Splash Page: For access to the Internet.\">

	<copy-right>
		<br><br>
		Nodogsplash $version.
	</copy-right>
	</div>
	</div>
	</body>
	</html>
"

# Define a login form
login_form="
	<form action=\"/nodogsplash_preauth/\" method=\"get\">
	<input type=\"hidden\" name=\"clientip\" value=\"$clientip\">
	<input type=\"hidden\" name=\"gatewayname\" value=\"$gatewayname\">
	<input type=\"hidden\" name=\"hid\" value=\"$hid\">
	<input type=\"hidden\" name=\"redir\" value=\"$requested\">
	<input type=\"text\" name=\"username\" value=\"$username\" autocomplete=\"on\" ><br>Name<br><br>
	<input type=\"email\" name=\"emailaddr\" value=\"$emailaddr\" autocomplete=\"on\" ><br>Email<br><br>
	<input type=\"submit\" value=\"Continue\" >
	</form><hr>
"

# Output the page common header
echo -e $header

# Check if the client is already logged in and has tapped "back" on their browser
# Make this a friendly message explaining they are good to go
if [ $status == "authenticated" ]; then
	echo "<p><big-red>You are already logged in and have access to the Internet.</big-red></p>"
	echo "<hr>"
	echo "<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>"
	echo -e $footer
	exit 0
fi

# For this simple example, we check that both the username and email address fields have been filled in.
# If not then serve the initial page, again if necessary.
# We are not doing any specific validation in this example, but here is the place to do it if you need to.
#
# Note if only one of username or email address fields is entered then that value will be preserved
# and displayed on the page when it is re-served.
#
# Note also $clientip, $gatewayname and $requested (redir) must always be preserved
#
if [ -z $username ] || [ -z $emailaddr ]; then
	echo "<big-red>Welcome!</big-red><italic-black> To access the Internet you must enter your Name and Email Address</italic-black><hr>"
	echo -e $login_form
else
	# If we got here, we have both the username and emailaddr fields as completed on the login page on the client,
	# so we will now call ndsctl to get client data we need to authenticate and add to our log.

	# Variables returned from ndsctl are listed in $varlist.

	# We at least need the client token to authenticate.
	# In this example we will also log the client mac address.

	varlist="id ip mac added active duration token state downloaded avg_down_speed uploaded avg_up_speed"
	clientinfo=$(ndsctl json $clientip)

	if [ -z $clientinfo ]; then
		echo "<big-red>Sorry!</big-red><italic-black> The portal is busy, please try again.</italic-black><hr>"
		echo -e $login_form
		echo -e $footer
		exit 0
	else
		for var in $varlist; do
			eval $var=$(echo "$clientinfo" | grep $var | awk -F'"' '{print $4}')
		done
	fi

	tok=$token
	clientmac=$mac

	# We now output the "Thankyou page" with a "Continue" button.

	# This is the place to include information or advertising on this page,
	# as this page will stay open until the client user taps or clicks "Continue"

	# Be aware that many devices will close the login browser as soon as
	# the client user continues, so now is the time to deliver your message.

	echo "<big-red>Thankyou!</big-red>"
	echo "<br><b>Welcome $username</b>"

	# Add your message here:
	# You could retrieve text or images from a remote server using wget or curl
	# as this router has Internet access whilst the client device does not (yet).
	echo "<br><italic-black> Your News or Advertising could be here, contact the owners of this Hotspot to find out how!</italic-black>"

	echo "<form action=\"/nodogsplash_auth/\" method=\"get\">"
	echo "<input type=\"hidden\" name=\"tok\" value=\"$tok\">"
	echo "<input type=\"hidden\" name=\"redir\" value=\"$requested\"><br>"
	echo "<input type=\"submit\" value=\"Continue\" >"
	echo "</form><hr>"

	# In this example we have decided to log all clients who are granted access
	write_log
fi

# Output the page footer
echo -e $footer

# The output of this script could of course be much more complex and
# could easily be used to conduct a dialogue with the client user.
#

