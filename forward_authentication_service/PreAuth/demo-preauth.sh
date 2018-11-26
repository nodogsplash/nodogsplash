#!/bin/sh
query_enc="$1"

# query string is sent from NDS urlencoded, so decode it here:
query=$(printf "${query_enc//%/\\x}")

# parse for what we are looking for:
clientip="$(echo $query | awk -F '&' '{print $1;}' | awk -F '=' '{print $2;}')"
gatewayname="$(echo $query | awk -F '&' '{print $2;}' | awk -F '=' '{print $2;}')"
requested="$(echo $query | awk -F '&' '{print $3;}' | awk -F '=' '{print $2;}')"
username="$(echo $query | awk -F '&' '{print $4;}' | awk -F '=' '{print $2;}')"
emailaddr="$(echo $query | awk -F '&' '{print $5;}' | awk -F '=' '{print $2;}')"

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

footer="
	<img src=\"/images/splash.jpg\" alt=\"Splash Page: For access to the Internet.\">\n
	<hr>
	<copy-right>Copyright &copy; The Nodogsplash Contributors 2004-2018.<br>This software is released under the GNU GPL license.</copy-right>\n
	\n
	</body>\n
	</html>\n
"

echo -e $header

if [ $requested == "authenticated" ]; then
	echo "<p><big-red>You are already logged in and have access to the Internet.</big-red></p>"
	echo "<hr>"
	echo "<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>"
	echo -e $footer
	exit 0
fi

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
	tok="$(ndsctl json $clientip | grep token | cut -c 10- | cut -c -8)"
	clientmac="$(ndsctl json $clientip | grep mac | grep mac | cut -c 8- | cut -c -17)"

	echo "<big-red>Thankyou!</big-red>"
	echo "<br><italic-black> Your News or Advertising could be here, contact the owners of this Hotspot to find out how!</italic-black>"
	echo "<form action=\"/nodogsplash_auth/\" method=\"get\">"
	echo "<input type=\"hidden\" name=\"tok\" value=\"$tok\"><br>"
	echo "<input type=\"hidden\" name=\"redir\" value=\"$requested\"><br>"
	echo "<input type=\"submit\" value=\"Continue\" >"
	echo "</form><hr>"
	echo "$(date) Username=$username Email Address=$emailaddr mac address=$clientmac" >> /tmp/ndslog.log
fi

echo -e $footer


