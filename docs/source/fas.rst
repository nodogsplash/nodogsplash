Forwarding Authentication Service (FAS)
#######################################

Overview
********

Nodogsplash (NDS) supports external (to NDS) authentication service via simple configuration options.

These options are:
 1. **fasport**. This enables Forwarding Authentication Service (FAS). Redirection is changed from splash.html to a FAS. The value is the IP port number of the FAS.
 2. **fasremoteip**. If set, this is the remote ip address of the FAS, if not set it will take the value of the NDS gateway address.
 3. **faspath**. This is the path to the login page on the FAS.
 4. **fas_secure_enable**. If set to "1", authaction and the client token are not revealed and it is the responsibility of the FAS to request the token from NDSCTL. If set to "0", the client token is sent to the FAS in clear text in the query string of the redirect along with authaction and redir.

.. note::
 FAS (and Preauth/FAS) enables pre authentication processing. NDS authentication is the process that NDS uses to allow a client device to access the Internet through the Firewall. In contrast, Forward Authentication is a process of "Credential Verification", after which FAS, if the verification process is successful, passes the client token to NDS for access to the Internet to be granted.


Using FAS
*********

**Note**:
All addresses (with the exception of fasremoteip) are relative to the *client* device, even if the FAS is located remotely.

When FAS is enabled, NDS automatically configures access to the FAS service.

The FAS service must serve an http splash of its own to replace the NDS splash.html.
Typically, the FAS service will be written in PHP or any other language that can provide dynamic web content.

FAS can then provide an action form for the client, typically requesting login, or self account creation for login.

The FAS can be on the same device as NDS, on the same local area network as NDS, or on an Internet hosted web server.

Security
********

**If FAS Secure is enabled** (fas_secure_enabled = 1, the default), NDS will supply only the gateway name, the client IP address and the originally requested URL in the query string in the redirect to FAS.

For example:

`http://fasremoteip:fasport/faspath?gatewayname=[gatewayname]&clientip=[clientip]&redir=[requested-url]`

It is the responsibility of FAS to obtain the unique client token allocated by NDS as well as constructing the return URL to NDS.

The return url will be constructed by FAS from predetermined knowledge of the configuration of NDS using gatewayname as an identifier.

The client's unique access token will be obtained from NDS by the FAS making a call to the ndsctl tool.

For example, the following command returns just the token:

`ndsctl json $clientip | grep token | cut -c 10- | cut -c -8`

If the client successfully authenticates in the FAS, FAS will return the unique token to NDS to finally allow the client access to the Internet.

A Secure Internet based FAS is best implemented as a two stage process, first using a local FAS, that in turn accesses an https remote FAS using tools such as curl or wget.

**If FAS Secure is disabled** (fas_secure_enabled = 0), NDS sends the token and other information to FAS as clear text.

For example:

`http://fasremoteip:fasport/faspath?authaction=http://gatewayaddress:gatewayport/nodogsplash_auth/?clientip=[clientip]&gatewayname=[gatewayname]&tok=[token]&redir=[requested_url]`

Clearly in this case, a knowledgeable user could bypass FAS, so running fas_secure_enabled = 1, the default, is recommended.

**Post FAS processing**.

Once the client has been authenticated by the FAS, NDS must then be informed to allow the client to have access to the Internet.

This is done by accessing NDS at a special virtual URL.
This is of the form:
`http://gatewayaddress:gatewayport/nodogsplash_auth/?tok=[token]&redir=[landing_page_url]`

This is most commonly done using an html form of method GET.
The parameter redir can be the client's originally requested URL sent by NDS, or more usefully, the URL of a suitable landing page.

However, be aware that many client CPD processes will **automatically close** the landing page as soon as Internet access is detected.

**Manual Access of NDS Virtual URL**

If the user of an already authenticated client device manually accesses the NDS Virtual URL, they will be redirected back to FAS with the "status" query string.

This will be of the form:

`http://fasremoteip:fasport/faspath?clientip=[clientip]&gatewayname=[gatewayname]&status=authenticated`

FAS should then serve a suitable error page informing the client user that they are already logged in.


Running FAS on your Nodogsplash router
**************************************

A FAS service will run quite well on uhttpd (the web server that serves Luci) on an OpenWrt supported device with 8MB flash and 32MB ram but shortage of ram may well be an issue if more than two or three clients log in at the same time.

For this reason a device with a minimum of 8MB flash and 64MB ram is recommended.

**Running on uhttpd with PHP**:

Although port 80 is the default for uhttpd, it is reserved for Captive Portal Detection so cannot be used for FAS. uhttpd can however be configured to operate on more than one port. We will use port 2080 in this example.

 Install the modules php7 and php7-cgi on OpenWrt for a simple example. Further modules may be required depending on your requirements.

To enable FAS with php in uhttpd you must add the lines:

  ``list listen_http	0.0.0.0:2080``

  ``list interpreter ".php=/usr/bin/php-cgi"``

to the /etc/config/uhttpd file in the config uhttpd 'main' or first section.

The two important NDS options to set will be:

 1. fasport. We will use port 2080 for uhttpd

 2. faspath. Set to, for example, /myfas/fas.php,
    your FAS files being placed in /www/myfas/

**Note 1**:

 A typical Internet hosted Apache/PHP **shared** server will be set up to serve multiple domain names.

 To access yours, use:

  fasremoteip = the **ip address** of the remote server

  and, for example,

  faspath = /domainname/pathto/myfas/fas.php

  or

  faspath = /accountname/pathto/myfas/fas.php

 If necessary, contact your hosting service provider.


**Note 2:**

 The configuration file /etc/config/nodogsplash contains the line "option enabled 1".

 If you have done something wrong and locked yourself out, you can still SSH to your router and stop NoDogSplash (ndsctl stop) to fix the problem.

Using the simple example files
******************************

Assuming you want to run the FAS example demo locally under uhttpd on the same OpenWrt device that is running NDS, configured as above, do the following.

 (Under other operating systems you may need to edit the nodogsplash.conf file in /etc/nodogsplash instead, but the process is very similar.)

First you should obtain the demo files by downloading the Nodogsplash zip file from

 https://github.com/nodogsplash/nodogsplash/

Then extract the php files from the folder

 "forward_authentication_service/nodog/"

**OpenWrt and uhttpd:**

 * Create a folder /www/nodog/

 * Place the files fas.php, landing.php, css.php, querycheck.php, tos.php, users.dat in /www/nodog/

 * Edit the file /etc/config/nodogsplash

  adding the lines:

    ``option fasport '2080'``

    ``option faspath '/nodog/fas.php'``

    ``option fas_secure_enabled '0'``

 * Restart uhttpd using the command "service uhttpd restart".

 * Restart NDS using the command "service nodogsplash restart".
