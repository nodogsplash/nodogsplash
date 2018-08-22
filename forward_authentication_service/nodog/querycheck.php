<?php
echo"<b style=\"color:red;\">Sorry! Something seems to have gone wrong!</b>";
echo"<br><b>Most likely BinAuth post authentication failed or your session has expired.<br>Please click the button to try again.</b>";
echo"<form>";
echo"<INPUT TYPE=\"button\" VALUE=\"Continue\" onClick=\"window.location.href='".$userurl."'\">";
echo"</form>";
echo"<div style=\"font-size:0.7em;\">\n";
echo"<hr>&copy; Blue Wave Projects and Services 2015-".date("Y").".</div>\n";
echo"</div>\n";
exit();
?>



