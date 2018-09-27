Customising nodogsplash
########################

After initial installation, Nogogsplash (NDS) should be working in its most basic mode and client Captive Portal Detection (CPD) should pop up the default splash page.

Before attempting to customise NDS you should ensure it is working in this basic mode before you start.

NDS reads its configuration file when it starts up but the location of this file varies depending on the operating system.

As NDS is a package that requires hardware configured as an IP router, perhaps the most common installation is using OpenWrt. However NDS can be compiled to run on most Linux distributions, the most common being Debian or one of its popular variants (eg Raspbian).

If NDS is working in the default, post installation mode, then you will have met the NDS dependencies and can now move on to your own customisation.

The Configuration File
**********************

In OpenWrt, or operating systems supporting UCI (such as LEDE) the configuration is kept in the file:

  ``/etc/config/nodogsplash``


In other operating systems the configuration is kept in the file:

  ``/etc/nodogsplash/nodogsplash.conf``

Both of these files contain a full list of options and can be edited directly. A restart of NDS is required for any changes to take effect.

In the case of OpenWrt though, once you are confident in your configuration requirements you can use UCI to read and set any of the configuration options using simple commands, making this very convenient if making changes from scripts, such as those you may write to use with Binauth and FAS.

For example, to list the full configuration, at the command line type:

.. code-block:: sh

  uci show nodogsplash

To display the Gateway Name, type:

.. code-block:: sh

  uci get nodogsplash.@nodogsplash[0].gatewayname

To set the Gateway Name to a new value, type:

.. code-block:: sh

  uci set nodogsplash.@nodogsplash[0].gatewayname='my new gateway'

To add a new firewall rule allowing access to another service running on port 8888 on the router, type:

.. code-block:: sh

 uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow
 tcp port 8888'

Finally you must tell UCI to commit your changes to the configuration file:

.. code-block:: sh

  uci commit nodogsplash

The Splash Page
***************

The default simple splash page can be found at:

  ``/etc/nodogsplash/htdocs/splash.html``

When the splash page is served, the following variables in the page are
replaced by their values:

* *$gatewayname* The value of GatewayName as set in nodogsplash.conf.
* *$authtarget* A URL which encodes a unique token and the URL of the user's   original web request. If nodogsplash receives a request at this URL, it completes the authentication process for the client and replies to the request with a "302 Found" to the encoded originally requested URL.

  It should be noted however that, depending on vendor, the client's built in CPD may not respond to simple html links.

 An href link example that my prove to be problematical:

  ``<a href="$authtarget">Enter</a>``

 (You should instead use a GET-method HTML form to send this   information to the nodogsplash server; see below.)

* *$imagesdir* The directory in nodogsplash's web hierarchy where images to be displayed in the splash page must be located.
* *$tok*, *$redir*, *$authaction*, and *$denyaction* are available and should be used to write the splash page to use a GET-method HTML form instead of using $authtarget as the value of an href attribute to communicate with the nodogsplash server.

 *$authaction* and *$denyaction* are virtual urls used to inform NDS that a client should be authenticated or deauthenticated and are of the form:

 `http://gatewayaddress:gatewayport/nodogsplash_auth/`

 and

 `http://gatewayaddress:gatewayport/nodogsplash_deny/`


 A simple example of a GET-method form:

.. code::
   
   <form method='GET' action='$authaction'>
     <input type='hidden' name='tok' value='$tok'>
     <input type='hidden' name='redir' value='$redir'>
     <input type='submit' value='Click Here to Enter'>
   </form>

* *$clientip*, *$clientmac* and *$gatewaymac* The respective addresses
  of the client or gateway. This might be useful in cases where the data
  needs to be forwarded to some other place by the splash page itself.

* *$nclients* and *$maxclients* User stats. Useful when you need to
  display something like "n of m users online" on the splash site.

* *$uptime* The time Nodogsplash has been running.

 A list of all available variables are included in the splash.html file.

 If the user accesses the virtual url *$authaction* when already authenticated, a status page is shown:

 ``/etc/nodogsplash/htdocs/status.html``

 In the status.html file, the same variables as in the splash.html site can be used.

It should be noted when designing a custom splash page that for security reasons many client device CPD implementations:

 * Immediately close the browser when the client has authenticated.

 * Prohibit the use of href links.

 * Prohibit downloading of external files (including .css and .js, even if they are allowed in NDS firewall settings).

 * Prohibit the execution of javascript.

Also, note that any images you reference should reside in the subdirectory that is defined by *$imagesdir* (default: "images").
