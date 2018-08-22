<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
<meta http-equiv="Pragma" content="no-cache" />
<meta http-equiv="Expires" content="0" />
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms of Service</title>

<style>
<?php
include("css.php");
?>
p {text-align: left; margin-left: 0%; margin-right: 0%}
</style>
</head>
<body>
<?php
echo"<div class=\"offset\">"; 
echo"<hr><b>Terms of Service for use of this Hotspot.</b> <hr><b>Access is granted on a basis of trust that you will NOT misuse or abuse that access in any way.</b><hr><b>";

echo"<b>Please scroll down to read the Terms of Service in full or click the Continue button to return to the Acceptance Page</b>";
#echo"<hr>";
echo"<form>";
echo"<input type=\"button\" VALUE=\"Continue\" onClick=\"history.go(-1);return true;\">";
echo"</form>";

echo"<hr><b>Proper Use</b>";

echo"<p>This Hotspot provides a wireless network that allows you to connect to the Internet. <br>
<b>Use of this Internet connection is provided in return for your FULL acceptance of these Terms Of Service.</b></p>";

echo"<p><b>You agree</b> that you are responsible for providing security measures that are suited for your intended use of the Service. For example, you shall take full responsibility for taking adequate measures to safeguard your data from loss.</p>";

echo"<p>While the Hotspot uses commercially reasonable efforts to provide a secure service, the effectiveness of those efforts cannot be guaranteed.
</p>";

echo"<p> <b>You may</b> use the technology provided to you by this Hotspot for the sole purpose of using the Service as described here. You must immediately notify the Owner of any unauthorized use of the Service or any other security breach.<br><br>We will give you an IP address each time you access the Hotspot, and it may change. 
<br><b>You shall not</b> program any other IP or MAC address into your device that accesses the Hotspot. You may not use the Service for any other reason, including reselling any aspect of the Service. Other examples of improper activities include, without limitation:</p>";
?>
<ol>
<li>downloading or uploading such large volumes of data that the performance of the Service becomes noticeably degraded for other users for a significant period;</li>

<li>attempting to break security, access, tamper with or use any unauthorized areas of the Service;</li>

<li>removing any copyright, trademark or other proprietary rights notices contained in or on the Service;</li>

<li>attempting to collect or maintain any information about other users of the Service (including usernames and/or email addresses) or other third parties for unauthorized purposes; </li>

<li>logging onto the Service under false or fraudulent pretenses;</li>

<li>creating or transmitting unwanted electronic communications such as SPAM or chain letters to other users or otherwise interfering with other user's enjoyment of the service;</li>

<li>transmitting any viruses, worms, defects, Trojan Horses or other items of a destructive nature; or </li>

<li>using the Service for any unlawful, harassing, abusive, criminal or fraudulent purpose. </li>
</ol>

<hr><b>Content Disclaimer</b>

<?php
echo"<p>The Hotspot Owners do not control and are not responsible for data, content, services, or products that are accessed or downloaded through the Service. The Owners may, but are not obliged to, block data transmissions to protect the Owner and the Public. </p>
The Owners, their suppliers and their licensors expressly disclaim to the fullest extent permitted by law, all express, implied, and statutary warranties, including, without limitation, the warranties of merchantability or fitness for a particular purpose. 
<br><br>The Owners, their suppliers and their licensors expressly disclaim to the fullest extent permitted by law any liability for infringement of proprietory rights and/or infringement of Copyright by any user of the system. Login details and device identities may be stored and be used as evidence in a Court of Law against such users.<br>";

echo"<hr><b>Limitation of Liability</b>
<p>Under no circumstances shall the Owners, their suppliers or their licensors be liable to any user or any third party on account of that party's use or misuse of or reliance on the Service.
</p>";

echo"<hr><b>Changes to Terms of Service and Termination</b>\n<p>We may modify or terminate the Service and these Terms of Service and any accompanying policies, for any reason, and without notice, including the right to terminate with or without notice, without liability to you, any user or any third party. Please review these Terms of Service from time to time so that you will be apprised of any changes.</p>\n";

echo"<p>We reserve the right to terminate your use of the Service, for any reason, and without notice. Upon any such termination, any and all rights granted to you by this Hotspot Owner shall terminate.</p>\n";

echo"<hr><b>Indemnity</b>";
$indemnitystr="<p><b>You agree</b> to hold harmless and indemnify the Owners of this Hotspot, their suppliers and licensors from and against any third party claim arising from or in any way related to your use of the Service, including any liability or expense arising from all claims, losses, damages (actual and consequential), suits, judgments, litigation costs and legal fees, of every kind and nature.</p>\n";
echo $indemnitystr;

echo"<hr>";
echo"<form>";
echo"<INPUT TYPE=\"button\" VALUE=\"Continue\" onClick=\"history.go(-1);return true;\">";
echo"</form>\n<hr>\n";
echo"</div>\n";
echo"</body>\n</html>\n";
?>




