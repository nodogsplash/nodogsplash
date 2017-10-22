<?php
// (c) Blue Wave Projects and Services 2015-2017." This software is released under the GNU GPL license.
//Set some defaults etc.
date_default_timezone_set("UTC");
$gatewayname=$tok=$tokchk=$orgurl=$clientip=$clientmac=$username=$password="";
$scriptname=str_replace("landing.php","css.php",$_SERVER['SCRIPT_NAME']);
$css=$_SERVER['DOCUMENT_ROOT'].$scriptname;

$header="Forwarding Authentication Landing Page";

function read_terms() {
//display the terms of sevrvice
echo("\n<form>\n<input type=\"button\" VALUE=\"Read Terms of Service\" onClick=\"location.href='tos.php'\" >\n</form>\n");
}


if(isset($_GET['gatewayname'])){$gatewayname=$_GET['gatewayname'];}
else{$gatewayname="NoDogSplash";}
if(isset($_GET['tok'])){$tok=$_GET['tok'];}
if(isset($_GET['tokchk'])){$tokchk=$_GET['tokchk'];}
if(isset($_GET['orgurl'])){$orgurl=$_GET['orgurl'];}
if(isset($_GET['clientip'])){$clientip=$_GET['clientip'];}
if(isset($_GET['clientmac'])){$clientmac=$_GET['clientmac'];}
if(isset($_GET['username'])){$username=$_GET['username'];}

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

echo"<hr><b style=\"font-size:1.25em;color:red;\">Welcome \"".$username."\".<br> You are logged in.</b><br><hr>";
echo"<b style=\"font-size:1em;color:black;\">Thank you for accepting the Terms of Service.<br><br>You can now use your browser and device APPs as you normally would.</b><hr>";
read_terms();

echo"<hr></div>\n";
echo "<div style=\"font-size:0.7em;\">\n";
echo "&copy; Blue Wave Projects and Services 2015-".date("Y")." This software is released under the GNU GPL license.";
echo"</div>\n";
echo"</body></html>";
?>

