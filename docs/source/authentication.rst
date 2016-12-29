Authentication
##############

Site-wide username and password
*******************************

Nodogsplash can be configured to require a username and/or password to be
entered on the splash page as part of the authentication process. Since the
username and password are site-wide (not per user), and they are sent in the
clear using HTTP GET, this is not a secure mechanism.
To enable this, edit *nodogsplash.conf* to set parameters *PasswordAuthentication*,
*UsernameAuthentication*, *Password*, *Username*, and *PasswordAttempts* as desired.
Then the splash page must use a GET-method HTML form to send user-entered
username and/or password as values of variables *nodoguser* and *nodogpass*
respectively, along with others as required, to the server. For example:

.. code::

   <form method='GET' action='$authaction'>
   <input type='hidden' name='tok' value='$tok'>
   <input type='hidden' name='redir' value='$redir'>
   username: <input type='text' name='nodoguser' value='' size='12' maxlength='12'>
   <br>
   password: <input type='password' name='nodogpass' value='' size='12' maxlength='10'>
   <br>
   <input type='submit' value='Enter'>
   </form>

Forwarding authentication
*************************

Nodogsplash allows to call an external program for authentication using
the options BinVoucher/EnablePreAuth/ForceVoucher in nodogsplash.conf.
The given program for BinVoucher will be called using the clients MAC address as argument.
The output is expected to be the number of seconds the client is to be authenticated.
It may also contain the clients download and upload speed limit in KBits/s.
See the example configuration file for further details.
