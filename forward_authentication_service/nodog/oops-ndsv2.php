<?php
echo"<b><span style=\"color:red; font-style:normal;\">Sorry! Something seems to have gone wrong!</span></b>";
echo"<br><b>Most likely your connection timed out.<br>Please click the button to try again.</b>";
echo"<form>";
echo"<INPUT TYPE=\"button\" VALUE=\"Continue\" onClick=\"window.location.href='".$orgurl."'\">";
echo"</form>";
exit();
?>



