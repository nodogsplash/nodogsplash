<?php
/* (c) Blue Wave Projects and Services 2015-2020. This software is released under the GNU GPL license.

 This is a FAS script providing an example of remote Forward Authentication for Nodogsplash (NDS) on an http web server supporting PHP.

 The following NDS configurations must be set:
 1. fasport: Set to the port number the remote webserver is using (typically port 80)

 2. faspath: This is the path from the FAS Web Root to the location of this FAS script (not from the file system root).
	eg. /nds/fas-hid.php

 3. fasremoteip: The remote IPv4 address of the remote server eg. 46.32.240.41

 4. fasremotefqdn: The fully qualified domain name of the remote web server.
	This is required in the case of a shared web server (ie. a server that hosts multiple domains on a single IP),
	but is optional for a dedicated web server (ie. a server that hosts only a single domain on a single IP).
	eg. onboard-wifi.net

 5. faskey: Matching $key as set in this script (see below this introduction).
	This is a key phrase for NDS to encrypt the query string sent to FAS.
	It can be any combination of A-Z, a-z and 0-9, up to 16 characters with no white space.
	eg 1234567890

 6. fas_secure_enabled:  set to level 1
	The NDS parameters: clientip, clientmac, gatewayname, hid and redir
	are passed to FAS in the query string.


 This script requires the client user to enter their Fullname and email address. This information is stored in a log file kept
 in /tmp or the same folder as this script.

 This script requests the client CPD to display the NDS splash.jpg image directly from the 
	/etc/nodogsplash/htdocs/images folder of the NDS device.

 This script displays an example Terms of Service. You should modify this for your local legal juristiction.

 The script is provided as a fully functional alternative to the basic NDS splash page.
 In its present trivial form it does not do any verification, but serves as an example for customisation projects.

*/

$key="1234567890";
$authdir="nodogsplash_auth";

date_default_timezone_set("UTC");

if (isset($_SERVER['HTTPS'])) {
	$protocol="https://";
} else {
	$protocol="http://";
}

$fullname=$email=$clientip=$gatewayname=$gatewayaddress=$redir="";

$docroot=$_SERVER['DOCUMENT_ROOT'];
$me=$_SERVER['SCRIPT_NAME'];
$home=str_replace(basename($_SERVER['SCRIPT_NAME']),"",$_SERVER['SCRIPT_NAME']);

$header="NDS Captive Portal";

$invalid=false;

if (isset($_GET['hid']))  {
	$hid=$_GET['hid'];
	$clientip=$_GET['clientip'];
	$gatewayname=$_GET['gatewayname'];
	$gatewayaddress=$_GET['gatewayaddress'];
	$redir=$_GET['redir'];
} else {
	$invalid=true;
}

if (isset($_GET["status"])) {
	$clientip=$_GET['clientip'];
	$gatewayname=$_GET['gatewayname'];
	$gatewayaddress=$_GET['gatewayaddress'];
	$redir="";
	$loggedin=true;
	$invalid=false;
}

if (!isset($gatewayname)) {
	$gatewayname="NoDogSplash";
}

$landing=false;
$terms=false;

if (isset($_GET["redir"])) {
	$redir=$_GET["redir"];
	#$landing=true;
}

if (isset($_GET["terms"])) {
	$terms=true;
}

// Add headers to stop browsers from cacheing 
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Cache-Control: no-cache");
header("Pragma: no-cache");


$imagepath="http://".$gatewayaddress."/images/splash.jpg";


//Output our responsive page
echo"<!DOCTYPE html>\n<html>\n<head>\n".
	"<meta charset=\"utf-8\" />\n".
	"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";

echo "<link rel=\"shortcut icon\" href=".$imagepath." type=\"image/x-icon\">";


echo "<title>".$header."</title>\n"."<style>\n";
insert_css();
echo"\n</style>\n</head>\n<body>\n";

//page header
echo "<div class=\"offset\">\n";
echo "<hr><b style=\"color:blue;\">".$gatewayname.
	" </b><br><b>".$header."</b><br><hr>\n";
echo"<div class=\"insert\">\n";

echo "<img style=\"float:left; width:4em; height:4em;\" src=\"".$imagepath."\">";

if ($terms == true) {
	display_terms();
	footer();
	exit(0);
}

if ($landing == true) {
	echo "<p><big-red>You are now logged in and have access to the Internet.</big-red></p>";
	echo "<hr>";
	echo "<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>";
	echo "\n<form>\n<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='".$redir."'\" >\n</form>\n";
	read_terms($me, $clientip, $gatewayname, $gatewayaddress, $hid, $redir);
	footer();
	exit(0);
}

if (isset($_GET["status"])) {
	if ($_GET["status"] == "authenticated") {
		echo "<p><big-red>You are already logged in and have access to the Internet.</big-red></p>";
		echo "<hr>";
		echo "<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>";
		$hid=$redir="status";
		read_terms($me, $clientip, $gatewayname, $gatewayaddress, $hid, $redir);
		footer();
		exit(0);
	}
}
if (isset($_GET["fullname"])) {
	$fullname=ucwords($_GET["fullname"]);
}

if (isset($_GET["email"])) {
	$email=$_GET["email"];
}


//Initial Form
if ($fullname == "" or $email == "") {
	echo "<b>Enter Full Name and Email Address</b>\n";
	$me=$_SERVER['SCRIPT_NAME'];
	if ($invalid == true) {
		echo "<br><b style=\"color:red;\">ERROR! Incomplete data passed from NDS</b>\n";
	} else {
		read_terms($me, $clientip, $gatewayname, $gatewayaddress, $hid, $redir);
		echo "<form action=\"".$me."\" method=\"get\" >\n";
		echo "<input type=\"hidden\" name=\"clientip\" value=\"".$clientip."\">\n";
		echo "<input type=\"hidden\" name=\"gatewayname\" value=\"".$gatewayname."\">\n";
		echo "<input type=\"hidden\" name=\"gatewayaddress\" value=\"".$gatewayaddress."\">\n";
		echo "<input type=\"hidden\" name=\"hid\" value=\"".$hid."\">\n";
		echo "<input type=\"hidden\" name=\"redir\" value=\"".$redir."\">\n";
		echo "<hr>Full Name:<br>\n";
		echo "<input type=\"text\" name=\"fullname\" value=\"".$fullname."\">\n<br>\n";
		echo "Email Address:<br>\n";
		echo "<input type=\"email\" name=\"email\" value=\"".$email."\">\n<br><br>\n";
		echo "<input type=\"submit\" value=\"Accept Terms of Service\">\n</form>\n";
	}
} else {
	# Output the "Thankyou page" with a continue button
	# You could include information or advertising on this page
	# Be aware that many devices will close the login browser as soon as
	# the client taps continue, so now is the time to deliver your message.
	$authaction="http://".$gatewayaddress."/".$authdir."/";
	$tok=hash('sha256', $hid.$key);

	echo "<big-red>Thankyou!</big-red>\n".
		"<br><b>Welcome $fullname</b>\n".
		"<br><italic-black> Your News or Advertising could be here, contact the owners of this Hotspot to find out how!</italic-black>\n".
		"<form action=\"".$authaction."\" method=\"get\">\n".
		"<input type=\"hidden\" name=\"tok\" value=\"".$tok."\">\n".
		"<input type=\"hidden\" name=\"redir\" value=\"".$redir."\"><br>\n".
		"<input type=\"submit\" value=\"Continue\" >\n".
		"</form><hr>\n";
	read_terms($me, $clientip, $gatewayname, $gatewayaddress, $hid, $redir);

	# In this example we have decided to log all clients who are granted access
	# Note: the web server daemon must have read and write permissions to the folder defined in $logpath
	# By default $logpath is null so the logfile will be written to the folder this script resides in,
	# or the /tmp directory if on the NDS router

	$logpath="";

	if (file_exists("/etc/nodogsplash")) {
		$logpath="/tmp/";
	}

	$log=date('d/m/Y H:i:s', $_SERVER['REQUEST_TIME'])." Username=".$fullname." emailaddress=".$email."\n";

	$gwname=str_replace(" ", "_", trim($gatewayname));
	$logfile=$logpath.$gwname."_log.php";


	if (!file_exists($logfile)) {
		@file_put_contents($logfile, "<?php exit(0); ?>\n");
	}
	if (is_writable($logfile)) {
		file_put_contents($logfile, $log,  FILE_APPEND );
	}
}

footer();

// Functions:

function footer() {
	echo "<hr>\n</div>\n";
	echo "<div style=\"font-size:0.7em;\">\n";
	echo "&copy; The Nodogsplash Contributors 2004-".date("Y")."<br>";
	echo "&copy; Blue Wave Projects and Services 2015-".date("Y")."<br>".
		"This software is released under the GNU GPL license.\n";
	echo "</div>\n";
	echo "</div>\n";
	echo "</body>\n</html>\n";
}

function read_terms($me, $clientip, $gatewayname, $gatewayaddress, $hid, $redir) {
	//terms of service button
	echo "<form action=\"".$me."\" method=\"get\" >\n".
		"<input type=\"hidden\" name=\"terms\" value=\"terms\">\n".
		"<input type=\"hidden\" name=\"clientip\" value=\"".$clientip."\">\n".
		"<input type=\"hidden\" name=\"gatewayname\" value=\"".$gatewayname."\">\n".
		"<input type=\"hidden\" name=\"gatewayaddress\" value=\"".$gatewayaddress."\">\n".
		"<input type=\"hidden\" name=\"hid\" value=\"".$hid."\">\n".
		"<input type=\"hidden\" name=\"redir\" value=\"".$redir."\">\n".
		"<input type=\"submit\" value=\"Read Terms of Service\" >\n".
		"</form>\n";
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
	echo "
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

	input[type=text], input[type=email] {
		color: black;
		background: lightgrey;
	}

	input[type=submit], input[type=button] {
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
}

?>
