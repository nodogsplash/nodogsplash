<?php
// (c) Blue Wave Projects and Services 2015-2017." This software is released under the GNU GPL license.
date_default_timezone_set("UTC");
$users="users.dat";
$gatewayname=$tok=$tokchk=$redir=$orgurl=$authaction=$clientip=$clientmac=$username=$password="";

if (isset($_SERVER['HTTPS'])) {
	$protocol="https://";
} else {
	$protocol="http://";
}

$host=$_SERVER['HTTP_HOST'];
$home=str_replace("fas.php","",$_SERVER['SCRIPT_NAME']);
$redirscript=str_replace("fas.php","landing.php",$_SERVER['SCRIPT_NAME']);
$landing=$protocol.$host.$redirscript;
$validated="not tested";
$header="Forwarding Authentication Service for NoDogSplash - Simple Example";

if (isset($_GET['gatewayname'])) {
	$gatewayname=$_GET['gatewayname'];
} else {
	$gatewayname="NoDogSplash";
}

if (isset($_GET['tok'])) {$tok=$_GET['tok'];}
if (isset($_GET['tokchk'])) {$tokchk=$_GET['tokchk'];}
if (isset($_GET['redir'])) {$redir=$_GET['redir'];}
if (isset($_GET['orgurl'])) {$orgurl=$_GET['orgurl'];}
if (isset($_GET['authaction'])) {$authaction=$_GET['authaction'];}
if (isset($_GET['clientip'])) {$clientip=$_GET['clientip'];}
if (isset($_GET['clientmac'])) {$clientmac=$_GET['clientmac'];}

if (isset($_POST['username'])) {
	$username=$_POST['username'];
	$password=$_POST['password'];
	$gatewayname=$_POST['gatewayname'];
	$tok=$_POST['tok'];
	$tokchk=$_POST['tokchk'];
	$redir=$_POST['redir'];
	$orgurl=$_POST['orgurl'];
	$authaction=$_POST['authaction'];
	$clientip=$_POST['clientip'];
	$clientmac=$_POST['clientmac'];
}

// Add headers to stop browsers from cacheing 
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Cache-Control: no-cache");
header("Pragma: no-cache");

//Output our responsive page
echo"<!DOCTYPE html>\n<html>\n<head>\n";
echo"<meta charset=\"utf-8\" />\n";
echo"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
echo"<title>".$header.".</title>\n";
echo"<style>\n";
include("css.php");
echo"\n</style>\n</head>\n<body>\n";

//page header
echo "<div class=\"offset\">\n"; 
echo "<hr><b style=\"color:blue;\">".$gatewayname." </b><br><b>".$header."</b><br><hr>\n";
echo"<div class=\"box\" style=\"max-width:100%;\">\n";
//end of page header


#check for binauth nak
$split=explode("&orgurl=",$redir);
if (isset($split[1])) {
	$split=explode("&clientip=",$split[1]);
	$userurl=$split[0];
	include "querycheck.php";
}

# check for invalid token return #
if (isset($_GET['tokchk'])) {
	$userurl=$_GET['orgurl'];
	include "querycheck.php";
}

if (isset($_POST['username'])) {
	//Validate user supplied username and password
	if ($username!="") {
		//username is set to something
		if (file_exists($users)) {
			$handle=fopen($users,'r');
			while(! feof($handle)) {
				$line=fgets($handle);
				if (feof($handle)) {break;}
				list($user,$pass)=explode(", ",$line);
				if ($username==trim($user) and $password==trim($pass)) {
					$validated="yes";
					break;
				}
			}
			if($validated!="yes"){$validated="no";}
			fclose($handle);
		} else {
			echo"<br><b>Missing User Database</b><br>";
		}
	} else {
		$validated="no";
	}
} else {
	//Initial Form
	echo"<b>Enter Username and Password</b>";
	login($gatewayname, $tok, $tokchk, $redir, $orgurl,
		$authaction, $clientip, $clientmac, $username, $password);
}

if ($validated=="yes") {
	echo"<b style=\"color:red;\">Successful Login</b><hr>"; 
	acceptance($landing, $gatewayname, $tok, $tokchk, $redir, $orgurl,
		$authaction, $clientip, $clientmac, $username, $password);
}
if ($validated=="no") {
	echo"<b style=\"color:red;\">Invalid login attempt</b>";
	login($gatewayname, $tok, $tokchk, $redir, $orgurl,
			$authaction, $clientip, $clientmac, $username, "");
}

echo"</div>\n";
echo "<div style=\"font-size:0.7em;\">\n";
echo "&copy; Blue Wave Projects and Services 2015-".date("Y")." This software is released under the GNU GPL license.\n";
echo"</div>\n";
echo"</div>\n";
echo"</body>\n</html>\n";

//Functions
function read_terms() {
	//terms of service button
	echo"\n<form>\n<input type=\"button\" VALUE=\"Read Terms of Service\" onClick=\"location.href='tos.php'\" >\n</form>\n";
}

function acceptance($landing, $gatewayname, $tok, $tokchk, $redir, $orgurl,
			$authaction, $clientip, $clientmac, $username, $password) {
	read_terms();
	echo"\n<br>\n<form method='GET' action='" . $authaction . "'>\n";
	echo"<input type='hidden' name='tok' value='" . $tok . "'>\n";
	echo"<input type='hidden' name='redir' value='".$landing."?userurl=".$redir.
		"&amp;tok=".$tok."&amp;orgurl=".$redir."&amp;clientip=".$clientip.
		"&amp;clientmac=".$clientmac."&amp;username=".$username."&amp;gatewayname=".
		$gatewayname."&amp;tokchk=true'>\n";
	echo"<input type='submit' value='Accept Terms of Service'>\n</form>\n";
}

function login($gatewayname, $tok, $tokchk, $redir, $orgurl,
		$authaction, $clientip, $clientmac, $username, $password) {
	$me=$_SERVER['SCRIPT_NAME'];
	if ($authaction=="" or $authaction=="\$authaction") {
		echo"<br><b style=\"color:red;\">ERROR! Incomplete data passed from NDS</b>";
	} else {
		echo"<form action=\"".$me."\" method=\"post\" >\n";
		echo"<input type=\"hidden\" name=\"gatewayname\" value=\"" . $gatewayname . "\">\n";
		echo"<input type=\"hidden\" name=\"tok\" value=\"" . $tok . "\">\n";
		echo"<input type=\"hidden\" name=\"tokchk\" value=\"" . $tokchk . "\">\n";
		echo"<input type=\"hidden\" name=\"redir\" value=\"" . $redir . "\">\n";
		echo"<input type=\"hidden\" name=\"orgurl\" value=\"" . $orgurl . "\">\n";
		echo"<input type=\"hidden\" name=\"authaction\" value=\"" . $authaction . "\">\n";
		echo"<input type=\"hidden\" name=\"clientip\" value=\"" . $clientip . "\">\n";
		echo"<input type=\"hidden\" name=\"clientmac\" value=\"" . $clientmac . "\">\n";
		echo"<hr>Username:<br>";
		echo"<input type=\"text\" name=\"username\" value=\"" . htmlentities($username) . "\">\n<br>\n";
		echo"Password:<br>";
		echo"<input type=\"password\" name=\"password\" value=\"" . htmlentities($password) . "\">\n<br><br>\n";
		echo"<input type=\"submit\" value=\"Log In\">\n</form>\n<hr>\n";
	}
}

?>
