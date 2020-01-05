<?php
/* (c) Blue Wave Projects and Services 2015-2019. This software is released under the GNU GPL license.

 This is a FAS script providing an example of remote Forward Authentication for Nodogsplash (NDS) on an http web server supporting PHP.

 The following NDS configurations must be set:
 1. fasport: Set to the port number the remote webserver is using (typically port 80)

 2. faspath: This is the path from the FAS Web Root to the location of this FAS script (not from the file system root).
	eg. /nds/fas-aes.php

 3. fasremoteip: The remote IPv4 address of the remote server eg. 46.32.240.41

 4. fasremotefqdn: The fully qualified domain name of the remote web server.
	This is required in the case of a shared web server (ie. a server that hosts multiple domains on a single IP),
	but is optional for a dedicated web server (ie. a server that hosts only a single domain on a single IP).
	eg. onboard-wifi.net

 5. faskey: Matching $key as set in this script (see below this introduction).
	This is a key phrase for NDS to encrypt the query string sent to FAS.
	It can be any combination of A-Z, a-z and 0-9, up to 16 characters with no white space.
	eg 1234567890

 6. fas_secure_enabled:  set to level 2
	The NDS parameters: clientip, clientmac, gatewayname, client token, gatewayaddress, authdir and originurl
	are encrypted using fas_key and passed to FAS in the query string.

	The query string will also contain a randomly generated initialization vector to be used by the FAS for decryption.
	
	The "php-cli" package and the "php-openssl" module must both be installed for fas_secure level 2.

 Nodogsplash does not have "php-cli" and "php-openssl" as dependencies, but will exit gracefully at runtime if this package and module
 are not installed when fas_secure_enabled is set to level 2.

 The FAS must use the initialisation vector passed with the query string and the pre shared faskey to decrypt the required information.

 The remote web server (that runs this script) must have the "php-openssl" module installed (standard for most hosting services).

 This script requires the client user to enter their Fullname and email address. This information is stored in a log file kept
 in the same folder as this script.

 This script requests the client CPD to display the NDS splash.jpg image directly from the 
	/etc/nodogsplash/htdocs/images folder of the NDS device.

 This script displays an example Terms of Service. You should modify this for your local legal juristiction.

 The script is provided as a fully functional alternative to the basic NDS splash page.
 In its present trivial form it does not do any verification, but serves as an example for customisation projects.

 The script retreives the clientif string sent from NDS and displays it on the login form.
 "clientif" is of the form [client_local_interface] [remote_meshnode_mac] [local_mesh_if]
 The returned values can be used to dynamically modify the login form presented to the client,
 depending on the interface the client is connected to.
 eg. The login form can be different for an ethernet connection, a private wifi, a public wifi or a remote mesh network zone. 

*/

$key="1234567890";

date_default_timezone_set("UTC");

if (isset($_SERVER['HTTPS'])) {
	$protocol="https://";
} else {
	$protocol="http://";
}

$fullname=$email=$invalid="";
$cipher="AES-256-CBC";
$docroot=$_SERVER['DOCUMENT_ROOT'];
$me=$_SERVER['SCRIPT_NAME'];
$home=str_replace(basename($_SERVER['SCRIPT_NAME']),"",$_SERVER['SCRIPT_NAME']);

$header="NDS Captive Portal";


if (isset($_GET['fas']) and isset($_GET['iv']))  {
	$string=$_GET['fas'];
	$iv=$_GET['iv'];
	$decrypted=openssl_decrypt( base64_decode( $string ), $cipher, $key, 0, $iv );
	$dec_r=explode(", ",$decrypted);

	foreach ($dec_r as $dec) {
		list($name,$value)=explode("=",$dec);
		if ($name == "clientip") {$clientip=$value;}
		if ($name == "clientmac") {$clientmac=$value;}
		if ($name == "gatewayname") {$gatewayname=$value;}
		if ($name == "tok") {$tok=$value;}
		if ($name == "gatewayaddress") {$gatewayaddress=$value;}
		if ($name == "authdir") {$authdir=$value;}
		if ($name == "originurl") {$originurl=$value;}
		if ($name == "clientif") {$clientif=$value;}
	}
	$client_zone_r=explode(" ",trim($clientif));

	if ($client_zone_r[1] == "") {
		$client_zone="LocalZone:".$client_zone_r[0];
	} else {
		$client_zone="MeshZone:".str_replace(":","",$client_zone_r[1]);
	}

} else if (isset($_GET["status"])) {
	$gatewayname=$_GET["gatewayname"];
	$gatewayaddress=$_GET["gatewayaddress"];
	$originurl="";
	$loggedin=true;
} else {
	$invalid=true;
}

if (!isset($gatewayname)) {
	$gatewayname="NoDogSplash";
}

$landing=false;
$terms=false;

if (isset($_GET["originurl"])) {
	$originurl=$_GET["originurl"];
	$landing=true;
} else if (isset($_GET["terms"])) {
	$gatewayname=$_GET["gatewayname"];
	$terms=true;
}

// Add headers to stop browsers from cacheing 
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Cache-Control: no-cache");
header("Pragma: no-cache");

if (isset($gatewayaddress)) {
	$imagepath="http://".$gatewayaddress."/images/splash.jpg";
} else {
	$imagepath="";
}

//Output our responsive page

$css=insert_css();
$header="
	<!DOCTYPE html>
	<html>
	<head>
	<meta http-equiv=\"Cache-Control\" content=\"no-cache, no-store, must-revalidate\">
	<meta http-equiv=\"Pragma\" content=\"no-cache\">
	<meta http-equiv=\"Expires\" content=\"0\">
	<meta charset=\"utf-8\">
	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
	<link rel=\"shortcut icon\" href=".$imagepath." type=\"image/x-icon\">
	<style>$css</style>
	<title>$gatewayname.</title>
	</head>
	<body>
	<div class=\"offset\">
	<med-blue>$gatewayname.</med-blue>
	<div class=\"insert\" style=\"max-width:100%;\">
	<hr>
";

#footer
if (isset($gatewayaddress)) {
	$image="<img style=\"float:left; width:7em; height:7em;\" src=\"".$imagepath."\">";
}

$footer="<hr>
	<div style=\"font-size:0.5em;\">
	$image
	&copy; The Nodogsplash Contributors 2004-".date("Y")."<br>
	&copy; Blue Wave Projects and Services 2015-".date("Y")."<br>
	This software is released under the GNU GPL license.<br><br><br><br><br>
	</div>
	</div>
	</div>
	</body>
	</html>";


echo $header;

if ($terms == true) {
	display_terms();
	echo $footer;
	exit(0);
}

if ($landing == true) {
	echo "<p><big-red>You are now logged in and have access to the Internet.</big-red></p>
		<hr>
		<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>
		<form>\n<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='".$originurl."'\" >\n</form>\n";
	echo $footer;
	exit(0);
}

if (isset($_GET["status"])) {
	if ($_GET["status"] == "authenticated") {
		echo "<p><big-red>You are already logged in and have access to the Internet.</big-red></p>
			<hr>
			<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>";
		read_terms($me,$gatewayname);
		echo $footer;
		exit(0);
	}
}
if (isset($_GET["fullname"])) {
	$fullname=ucwords(htmlentities($_GET["fullname"]));
}

if (isset($_GET["email"])) {
	$email=$_GET["email"];
}


//Initial Form
if ($fullname == "" or $email == "") {
	echo "<big-red>Welcome!</big-red><br>
		<med-blue>You are connected to $client_zone</med-blue><br>";
	$me=$_SERVER['SCRIPT_NAME'];
	if ($invalid == true) {
		echo "<br><b style=\"color:red;\">ERROR! Incomplete data passed from NDS</b>\n";
	} else {
		read_terms($me, $gatewayname);
		echo "<form action=\"$me\" method=\"get\" >
			<input type=\"hidden\" name=\"fas\" value=\"$string\">
			<input type=\"hidden\" name=\"iv\" value=\"$iv\">
			<hr>Full Name:<br>
			<input type=\"text\" name=\"fullname\" value=\"$fullname\">
			<br>
			Email Address:<br>
			<input type=\"email\" name=\"email\" value=\"$email\">
			<br><br>
			<input type=\"submit\" value=\"Accept Terms of Service\">\n</form>\n";
	}
} else {
	# Output the "Thankyou page" with a continue button
	# You could include information or advertising on this page
	# Be aware that many devices will close the login browser as soon as
	# the client taps continue, so now is the time to deliver your message.
	$authaction="http://".$gatewayaddress."/".$authdir."/";

	echo "<big-red>Thankyou!</big-red>
		<br><b>Welcome $fullname</b>
		<br><italic-black> Your News or Advertising could be here, contact the owners of this Hotspot to find out how!</italic-black>
		<form action=\"$authaction\" method=\"get\">
		<input type=\"hidden\" name=\"tok\" value=\"$tok\">
		<input type=\"hidden\" name=\"redir\" value=\"".urldecode($originurl)."\"><br>
		<input type=\"submit\" value=\"Continue\" >
		</form><hr>\n";
	read_terms($me,$gatewayname);

	# In this example we have decided to log all clients who are granted access
	# Note: the web server daemon must have read and write permissions to the folder defined in $logpath
	# By default $logpath is null so the logfile will be written to the folder this script resides in,
	# or the /tmp directory if on the NDS router

	$logpath="";

	if (file_exists("/etc/nodogsplash")) {
		$logpath="/tmp/";
	}

	$log=date('d/m/Y H:i:s', $_SERVER['REQUEST_TIME'])." Username=". html_entity_decode($fullname)." emailaddress=".$email.
		" macaddress=".$clientmac." clientzone=".$client_zone." useragent=".$_SERVER['HTTP_USER_AGENT']."\n";

	$gwname=str_replace(" ", "_", trim($gatewayname));
	$logfile=$logpath.$gwname."_log.php";


	if (!file_exists($logfile)) {
		@file_put_contents($logfile, "<?php exit(0); ?>\n");
	}
	if (is_writable($logfile)) {
		file_put_contents($logfile, $log,  FILE_APPEND );
	}
}

echo $footer;

// Functions:

function read_terms($me, $gatewayname) {
	//terms of service button
	echo "<form action=\"$me\" method=\"get\" >
		<input type=\"hidden\" name=\"terms\" value=\"terms\">
		<input type=\"hidden\" name=\"gatewayname\" value=\"$gatewayname\">
		<input type=\"submit\" value=\"Read Terms of Service\" >\n</form>\n";
}

function display_terms () {
	echo "<b style=\"color:red;\">Privacy.</b><br>\n".
		"<b>By logging in to the system, you grant your permission for this system to store the data you provide ".
		"along with the networking parameters of your device that the system requires to function.<br>".
		"All information collected by this system is stored in a secure manner.<br>".
		"All we ask for is your name and an email address in return for unrestricted FREE Internet access.</b><hr>";

	echo "<b style=\"color:red;\">Terms of Service for this Hotspot.</b> <br>\n".
		"<b>Access is granted on a basis of trust that you will NOT misuse or abuse that access in any way.</b><hr><b>\n";

	echo "<b>Please scroll down to read the Terms of Service in full or click the Continue button to return to the Acceptance Page</b>\n";

	echo "<form>\n".
		"<input type=\"button\" VALUE=\"Continue\" onClick=\"history.go(-1);return true;\">\n".
		"</form>\n";

	echo "<hr><b>Proper Use</b>\n";

	echo "<p>This Hotspot provides a wireless network that allows you to connect to the Internet. <br>\n".
		"<b>Use of this Internet connection is provided in return for your FULL acceptance of these Terms Of Service.</b></p>\n";

	echo "<p><b>You agree</b> that you are responsible for providing security measures that are suited for your intended use of the Service. \n".
		"For example, you shall take full responsibility for taking adequate measures to safeguard your data from loss.</p>\n";

	echo "<p>While the Hotspot uses commercially reasonable efforts to provide a secure service, \n".
		"the effectiveness of those efforts cannot be guaranteed.</p>\n";

	echo "<p> <b>You may</b> use the technology provided to you by this Hotspot for the sole purpose \n".
		"of using the Service as described here. \n".
		"You must immediately notify the Owner of any unauthorized use of the Service or any other security breach.<br><br>\n".
		"We will give you an IP address each time you access the Hotspot, and it may change.\n".
		"<br><b>You shall not</b> program any other IP or MAC address into your device that accesses the Hotspot. \n".
		"You may not use the Service for any other reason, including reselling any aspect of the Service. \n".
		"Other examples of improper activities include, without limitation:</p>\n";

	echo	"<ol>\n".
			"<li>downloading or uploading such large volumes of data that the performance of the Service becomes \n".
				"noticeably degraded for other users for a significant period;</li>\n".
			"<li>attempting to break security, access, tamper with or use any unauthorized areas of the Service;</li>\n".
			"<li>removing any copyright, trademark or other proprietary rights notices contained in or on the Service;</li>\n".
			"<li>attempting to collect or maintain any information about other users of the Service \n".
				"(including usernames and/or email addresses) or other third parties for unauthorized purposes; </li>\n".
			"<li>logging onto the Service under false or fraudulent pretenses;</li>\n".
			"<li>creating or transmitting unwanted electronic communications such as SPAM or chain letters to other users \n".
				"or otherwise interfering with other user's enjoyment of the service;</li>\n".
				"<li>transmitting any viruses, worms, defects, Trojan Horses or other items of a destructive nature; or </li>\n".
			"<li>using the Service for any unlawful, harassing, abusive, criminal or fraudulent purpose. </li>\n".
		"</ol>\n";

	echo "<hr><b>Content Disclaimer</b>\n";

	echo "<p>The Hotspot Owners do not control and are not responsible for data, content, services, or products \n".
		"that are accessed or downloaded through the Service. \n".
		"The Owners may, but are not obliged to, block data transmissions to protect the Owner and the Public. </p>\n".
		"The Owners, their suppliers and their licensors expressly disclaim to the fullest extent permitted by law, \n".
		"all express, implied, and statutary warranties, including, without limitation, the warranties of merchantability \n".
		"or fitness for a particular purpose.\n".
		"<br><br>The Owners, their suppliers and their licensors expressly disclaim to the fullest extent permitted by law \n".
		"any liability for infringement of proprietory rights and/or infringement of Copyright by any user of the system. \n".
		"Login details and device identities may be stored and be used as evidence in a Court of Law against such users.<br>\n";

	echo "<hr><b>Limitation of Liability</b>\n".
			"<p>Under no circumstances shall the Owners, their suppliers or their licensors be liable to any user or \n".
			"any third party on account of that party's use or misuse of or reliance on the Service.</p>\n";

	echo "<hr><b>Changes to Terms of Service and Termination</b>\n".
		"<p>We may modify or terminate the Service and these Terms of Service and any accompanying policies, \n".
		"for any reason, and without notice, including the right to terminate with or without notice, \n".
		"without liability to you, any user or any third party. Please review these Terms of Service \n".
		"from time to time so that you will be apprised of any changes.</p>\n";

	echo "<p>We reserve the right to terminate your use of the Service, for any reason, and without notice. \n".
		"Upon any such termination, any and all rights granted to you by this Hotspot Owner shall terminate.</p>\n";

	echo"<hr><b>Indemnity</b>\n".
		"<p><b>You agree</b> to hold harmless and indemnify the Owners of this Hotspot, \n".
		"their suppliers and licensors from and against any third party claim arising from \n".
		"or in any way related to your use of the Service, including any liability or expense arising from all claims, \n".
		"losses, damages (actual and consequential), suits, judgments, litigation costs and legal fees, of every kind and nature.</p>\n";

	echo "<hr>\n";
	echo "<form>\n".
		"<input type=\"button\" VALUE=\"Continue\" onClick=\"history.go(-1);return true;\">\n".
		"</form>\n";
}

function insert_css() {
	$css="
	body {
		background-color: lightgrey;
		color: black;
		margin-left: 5%;
		margin-right: 5%;
		text-align: left;
	}

	hr {
		display:block;
		margin-top:0.5em;
		margin-bottom:0.5em;
		margin-left:auto;
		margin-right:auto;
		border-style:inset;
		border-width:5px;
	} 

	.offset {
		background: rgba(300, 300, 300, 0.6);
		margin-left:auto;
		margin-right:auto;
		max-width:600px;
		min-width:200px;
		padding: 5px;
	}

	.insert {
		background: rgba(350, 350, 350, 0.7);
		border: 2px solid #aaa;
		border-radius: 4px;
		min-width:200px;
		max-width:100%;
		padding: 5px;
	}

	img {
		width: 40%;
		max-width: 180px;
		margin-left: 0%;
		margin-right: 5%;
	}

	input[type=text], input[type=email], input[type=password] {
		font-size: 1em;
		line-height: 2.0em;
		height: 2.0em;
		color: black;
		background: lightgrey;
	}

	input[type=submit], input[type=button] {
		font-size: 1em;
		line-height: 2.0em;
		height: 2.0em;
		color: black;
		background: lightblue;
	}

	med-blue {
		font-size: 1.2em;
		color: blue;
		font-weight: bold;
		font-style: normal;
	}

	big-red {
		font-size: 1.5em;
		color: red;
		font-weight: bold;
	}

	italic-black {
		font-size: 1.0em;
		color: black;
		font-weight: bold;
		font-style: italic;
	}

	copy-right {
		font-size: 0.7em;
		color: darkgrey;
		font-weight: bold;
		font-style:italic;
	}

	";
	return $css;
}

?>
