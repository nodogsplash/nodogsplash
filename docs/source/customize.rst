Customizing nodogsplash
########################

The default shipped configuration is intended to be usable and reasonably
secure as-is for basic internet sharing applications, but it is customizable.

* To change basic nodogsplash settings, edit the configuration file:

  ``/etc/nodogsplash/nodogsplash.conf``

In the configuration file, a FirewallRule has the form:

  ``FirewallRule permission [protocol [port portrange] [to ip]``

where

* *permission* is required and must be allow, block, drop, log, or ulog.
* *protocol* is optional. If present, it must be tcp, udp, icmp, or all.
  Defaults to all.
* port *portrange* is optional. If present, protocol must be tcp or udp.
  portrange can be a single integer port number, or a colon-separated port
  range, e.g. 1024:1028. Defaults to all ports.
* *to ip* is optional. If present, ip must be a decimal dotted-quad IP address
  with optional mask. Defaults to 0.0.0.0/0, i.e. all addresses.

* To change the contents of the splash page, edit the splash page file:

  ``/etc/nodogsplash/htdocs/splash.html``

When the splash page is served, the following variables in the page are
replaced by their values:

* *$gatewayname* The value of GatewayName as set in nodogsplash.conf.
* *$authtarget* A URL which encodes a unique token and the URL of the user's
  original web request. If nodogsplash receives a request at this URL, it
  completes the authentication process for the client and replies to the
  request with a "302 Found" to the encoded originally requested
  URL. (Alternatively, you can use a GET-method HTML form to send this
  information to the nodogsplash server; see below.) As a simple example:

  ``<a href="$authtarget">Enter</a>``

* *$imagesdir* The directory in nodogsplash's web hierarchy where images to be
  displayed in the splash page must be located.
* *$tok*,*$redir*,*$authaction*, and *$denyaction* are also available and can be
  useful if you want to write the splash page to use a GET-method HTML form
  instead of using $authtarget as the value of an href attribute to
  communicate with the nodogsplash server. As a simple example:

.. code::
   
   <form method='GET' action='$authaction'>
     <input type='hidden' name='tok' value='$tok'>
     <input type='hidden' name='redir' value='$redir'>
     <input type='submit' value='Click Here to Enter'>
   </form>

* *$clientip*, *$clientmac* and *$gatewaymac* The respective addresses
  of the client or gateway. This might be usefull in cases where the data
  needs to be forwarded to some other place by the plash page itself.

* *$nclients* and *$maxclients* User stats. Usefull when you need to
  display something like "n of m users online" on the splash site.

* *$uptime* The time Nodogsplash is running.

* To change the appearance of informational and error pages which may
  occasionally be served by nodogsplash, edit the infoskel file:

 ``/etc/nodogsplash/htdocs/infoskel.html``

In this file, variables *$gatewayname*, *$version*, *$title*, and *$content* will be
replaced by their values. $title is a summary of the information or kind of
error; *$content* is the content of the information or error message.

