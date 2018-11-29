#!/bin/sh
# Get the urlencoded querystring
query_enc="$1"

# The query string is sent to us from NDS in a urlencoded form,
# so we must decode it here so we can parse it:
query=$(printf "${query_enc//%/\\x}")

# In this example script we want to ask the client user for
# their username and email address.
#
# We could ask for anything we like and add additional input to the html forms
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

# The query string NDS sends to us will always be of the following form:
# ?clientip=[clientipaddress]&gatewayname=[gatewayname]&redir=[originalurl]&var4=[data]&var5=[data]&var6......
#
# The first three variables will be clientip, gatewayname and redir
#
# We have chosen to name redir as $requested here as it is actually the originally requested url.
#
# There is one exception to this. If the client presses "back" on their browser NDS detects this
# and tells us by returning &status=authenticated instead of &redir=[originalurl]
# If we detect this we show a page telling the client they are already logged in.


# parse for what we are looking for in this example:
clientip="$(echo $query | awk -F '&' '{print $1;}' | awk -F '=' '{print $2;}')"
gatewayname="$(echo $query | awk -F '&' '{print $2;}' | awk -F '=' '{print $2;}')"
requested="$(echo $query | awk -F '&' '{print $3;}' | awk -F '=' '{print $2;}')"
username="$(echo $query | awk -F '&' '{print $4;}' | awk -F '=' '{print $2;}')"
emailaddr="$(echo $query | awk -F '&' '{print $5;}' | awk -F '=' '{print $2;}')"

# Define some common html as the first part of the page to be served by NDS
# Note this example uses the default splash.css provided by NDS and uses splash.jpg
# as the browser shortcut icon. You can decide how your PreAuth splash page will look
# by incorporating your own css and images.
header="
	<!DOCTYPE html>\n
	<html>
	<head>\n
	<meta http-equiv=\"Cache-Control\" content=\"no-cache, no-store, must-revalidate\">\n
	<meta http-equiv=\"Pragma\" content=\"no-cache\">\n
	<meta http-equiv=\"Expires\" content=\"0\">\n
	<meta charset=\"utf-8\">\n
	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n
	\n
	<link rel=\"shortcut icon\" href=\"/images/splash.jpg\" type=\"image/x-icon\">\n
	<link rel=\"stylesheet\" type=\"text/css\" href=\"/splash.css\">\n
	<title>$gatewayname Hotspot Gateway.</title>\n
	</head>\n
	\n
	<body>\n
	<med-blue>$gatewayname Hotspot Gateway.</med-blue>\n
	<hr>
"

# Define a common footer for every page served
footer="
	<img src=\"/images/splash.jpg\" alt=\"Splash Page: For access to the Internet.\">\n
	<hr>
	<copy-right>Copyright &copy; The Nodogsplash Contributors 2004-2018.<br>This software is released under the GNU GPL license.</copy-right>\n
	\n
	</body>\n
	</html>\n
"

# Output the page common header
echo -e $header

# Check if the client is already logged in and has tapped "back" on their browser
# Make this a friendly message explaining they are good to go
if [ $requested == "authenticated" ]; then
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
	echo "<big-red>Welcome!</big-red><italic-black> To access the Internet you must enter your Name and Email Address</italic-black>"
	echo "<form action=\"/nodogsplash_preauth/\" method=\"get\">"
	echo "<input type=\"hidden\" name=\"clientip\" value=\"$clientip\"><br>"
	echo "<input type=\"hidden\" name=\"gatewayname\" value=\"$gatewayname\"><br>"
	echo "<input type=\"hidden\" name=\"redir\" value=\"$requested\"><br>"
	echo "<input type=\"text\" name=\"username\" value=\"$username\" autocomplete=\"on\" >:Name<br><br>"
	echo "<input type=\"email\" name=\"emailaddr\" value=\"$emailaddr\" autocomplete=\"on\" >:Email<br><br>"
	echo "<input type=\"submit\" value=\"Continue\" >"
	echo "</form><hr>"
else
	# We have both fields, so get the token and in this case also the mac address
	tok="$(ndsctl json $clientip | grep token | cut -c 10- | cut -c -8)"
	clientmac="$(ndsctl json $clientip | grep mac | cut -c 8- | cut -c -17)"

	# Output the "Thankyou page" with a continue button
	# You could include information or advertising on this page
	# Be aware that many devices will close the login browser as soon as
	# the client taps continue, so now is the time to deliver your message.
	echo "<big-red>Thankyou!</big-red>"
	echo "<br><b>Welcome $username</b>"
	echo "<br><italic-black> Your News or Advertising could be here, contact the owners of this Hotspot to find out how!</italic-black>"
	echo "<form action=\"/nodogsplash_auth/\" method=\"get\">"
	echo "<input type=\"hidden\" name=\"tok\" value=\"$tok\"><br>"
	echo "<input type=\"hidden\" name=\"redir\" value=\"$requested\"><br>"
	echo "<input type=\"submit\" value=\"Continue\" >"
	echo "</form><hr>"

	# In this example we have decided to log all clients who are granted access
	echo "$(date) Username=$username Email Address=$emailaddr mac address=$clientmac" >> /tmp/ndslog.log
fi

# Output the page footer
echo -e $footer

# The output of this script could of course be much more complex and
# could easily be used to conduct a dialogue with the client user.
# 
