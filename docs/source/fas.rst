Forwarding Authentication Service (FAS)
#######################################

Overview
********

Nodogsplash (NDS) supports external (to NDS) authentication service via simple configuration options.

These options are:

    1. fasport. This enables Forwarding Authentication Service (FAS). Redirection is changed from splash.html to a FAS. The value is the IP port number of the FAS

    2. fasremoteip. If set, this is the remote ip address of the FAS, if not set it will take the value of the NDS gateway address.

    3. faspath. This is the path to the login page on the FAS.

    4. fas secure enable. If set to "1", authaction and the client token are not revealed and it is the responsibility of the FAS to request the token from NDSCTL. If set to "0", the client token is sent to the FAS in clear text in the query string of the redirect along with authaction and redir.


Using FAS
*********
When FAS is enabled, NDS automatically configures access to the FAS service.

The FAS service must serve an http splash of its own to replace the NDS splash.html.
Typically, the FAS service will be written in PHP or any other language that can provide dynamic web content.

FAS can then provide an action form for the client, typically requesting login, or self account creation for login.

The FAS can be on the same device as NDS, on the same local area network as NDS, or on an Internet hosted web server.

If FAS Secure is enabled, NDS will supply only the gateway name, the client IP address and the originally requested URL.

It is the responsibility of FAS to obtain the unique client token allocated by NDS.

If the client successfully authenticates in the FAS, FAS will return the unique token to NDS to finally allow the client access to the Internet.

If FAS Secure is disabled, the token is sent to FAS as clear text.

A FAS on the local network can obtain the user token by requesting it from NDS, using, for example SSH.

A Secure Internet based FAS is best implemented as a two stage process, first using a local FAS, that in turn accesses an https remote FAS using tools such as curl or wget.

Running FAS on your Nodogsplash router
**************************************

A FAS service will run quite well on uhttpd (the web server that serves Luci) on an OpenWrt supported device with 8MB flash and 32MB ram but shortage of ram may well be an issue if more than two or three clients log in at the same time. For this reason a device with a minimum of 8MB flash and 64MB ram is recommended.

Running on uhttpd with PHP:
Install the modules php7 and php7-cgi on LEDE for a simple example. Further modules may be required depending on your requirements.

To enable php in uhttpd you must add the line:

    list interpreter ".php=/usr/bin/php-cgi"

to the /etc/config/uhttpd file in the config uhttpd 'main' or first section.

The two important NDS options to set will be:
    1. fasport. By default this will be port 80 for uhttpd
    2. faspath. Set to, for example, /myfas/fas.php, your FAS files being placed in /www/myfas/

**Note 1**:  

    A typical Internet hosted Apache/PHP shared server will be set up to serve multiple domain names.

    To access yours, use

    fasremoteip = the ip address of the remote server

    and, for example,

    faspath = /domainname/pathto/myfas/fas.php

    or

    faspath = /accountname/pathto/myfas/fas.php

    If necessary, contact your hosting service provider.  


**Note 2:**

    The configuration file /etc/config/nodogsplash contains the line "option enabled 1".  

    If you have done something wrong and locked yourself out, you can still SSH to your router and stop NoDogSplash (ndsctl stop) to fix the problem.

