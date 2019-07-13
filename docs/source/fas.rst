Forwarding Authentication Service (FAS)
#######################################

Overview
********
Nodogsplash (NDS) has the ability to forward requests to a third party authentication service (FAS). This is enabled via simple configuration options.

These options are:
 1. **fasport**. This enables Forwarding Authentication Service (FAS). Redirection is changed from splash.html to a FAS. The value is the IP port number of the FAS.
 2. **fasremoteip**. If set, this is the remote ip address of the FAS, if not set it will take the value of the NDS gateway address.
 3. **fasremotefqdn** If set, this is the remote fully qualified domain name (FQDN) of the FAS
 4. **faspath**. This is the path from the FAS Web Root (not the file system root) to the FAS login page.
 5. **fas_secure_enable**. This can have three values, "0", "1", or "2" providing different levels of security.
 6. **faskey** Used in combination with fas_secure_enable level 2, this is a key phrase for NDS to encrypt the query string sent to FAS.
 
.. note::
 FAS (and Preauth/FAS) enables pre authentication processing. NDS authentication is the process that NDS uses to allow a client device to access the Internet through the Firewall. In contrast, Forward Authentication is a process of "Credential Verification", after which FAS, if the verification process is successful, passes the client token to NDS for access to the Internet to be granted.

Using FAS
*********

**Note**:
All addresses (with the exception of fasremoteip) are relative to the *client* device, even if the FAS is located remotely.

When FAS is enabled, NDS automatically configures firewall access to the FAS service.

The FAS service must serve an http splash of its own to replace the NDS splash.html.

Typically, the FAS service will be written in PHP or any other language that can provide dynamic web content.

FAS can then provide an action form for the client, typically requesting login, or self account creation for login.

The FAS can be on the same device as NDS, on the same local area network as NDS, or on an Internet hosted web server.

Security
********

**If FAS Secure is enabled** (Levels 1 (default), and 2), the client authentication token is kept secret until FAS verification is complete.

   **If set to "0"** the client token is sent to the FAS in clear text in the query string of the
   redirect along with authaction and redir.

   **If set to "1"**
   authaction and the client token are not revealed and it is the responsibility of the FAS to request the token from NDSCTL.

   **If set to "2"**
   clientip, clientmac, gatewayname, client token, gatewayaddress, authdir and originurl are encrypted using faskey and passed to FAS in the query string.

   The query string will also contain a randomly generated initialization vector to be used by the FAS for decryption.

   The cipher used is "AES-256-CBC".

   The "php-cli" package and the "php-openssl" module must both be installed for fas_secure level 2.

   Nodogsplash does not depend on this package and module, but will exit gracefully if this package and module are not installed when this level is set.

   The FAS must use the query string passed initialisation vector and the pre shared fas_key to decrypt the query string. An example FAS level 2 php script is preinstalled in the /etc/nodogsplash directory and also supplied in the source code.

**Option faskey must be set** if fas secure is set to level 2.

  Option faskey is used to encrypt the data sent by NDS to FAS.
  It can be any combination of A-Z, a-z and 0-9, up to 16 characters with no white space.

  This is used to create a sha256 digest that is in turn used to encrypt the data using the aes-256-cbc cypher.

  A random initialisation vector is generated for every encryption and sent to FAS with the encrypted data.

  Option faskey must be pre-shared with FAS.


Example FAS Query strings
*************************

  **Level 0** (fas_secure_enabled = 0), NDS sends the token and other information to FAS as clear text.

  `http://fasremoteip:fasport/faspath?authaction=http://gatewayaddress:gatewayport/nodogsplash_auth/?clientip=[clientip]&gatewayname=[gatewayname]&tok=[token]&redir=[requested_url]`

   Although the simplest to set up, a knowledgeable user could bypass FAS, so running fas_secure_enabled at level 1 or 2 is recommended.


  **Level 1** (fas_secure_enabled = 1), NDS sends only information required to identify, the instance of NDS, the client and the client's originally requested URL.

  `http://fasremotefqdn:fasport/faspath?gatewayname=[gatewayname]&clientip=[clientip]&redir=[requested-url]`

   It is the responsibility of FAS to obtain the unique client token allocated by NDS as well as constructing the return URL to NDS.

   The return url will be constructed by FAS from predetermined knowledge of the configuration of NDS using gatewayname as an identifier.

   The client's unique access token will be obtained from NDS by the FAS making a call to the ndsctl tool.

   For example, the following command returns just the token:

   `ndsctl json $clientip | grep token | cut -c 10- | cut -c -8`

  **Level 2** (fas_secure_enabled = 2), NDS sends enrypted information to FAS.

  `http://fasremotefqdn:fasport/faspath?fas=[aes-256-cbc data]&iv=[random initialisation vector]`

   It is the responsibility of FAS to decrypt the aes-256-cbc data it receives, using the pre shared faskey and the random initialisation vector.

  The decrypted string received by FAS will be of the form:
  [varname1]=[var1], [varname2]=[var2], ..... etc. (the separator being comma-space).

  eg `clientip=192.168.8.23, clientmac=04:15:52:6a:e4:ad, tok=770bfe05, originurl=.....`

  Variables sent by NDS in the encrypted string in NDS v4.0.0 are as follows:

  **clientip clientmac gatewayname tok gatewayaddress authdir originurl**

  Where:
   **tok** is the client token

   **gatewayaddress** is authentication address of NDS ie [nds_ip]:[nds_port]

   **authdir** is the NDS virtual authentication directory

  Future versions of NDS may send additional variables and the order of the variables in the decrypted string may also vary, so it is the responsiblity of FAS to parse the decrypted string for the variables it requires.

After Successful Verification by FAS
************************************

If the client is successfully verified by the FAS, FAS will return the unique token to NDS to finally allow the client access to the Internet.


Post FAS processing
*******************

Once the client has been authenticated by the FAS, NDS must then be informed to allow the client to have access to the Internet.

 This is done by accessing NDS at a special virtual URL.

 This virtual URL is of the form:

 `http://[nds_ip]:[nds_port]/[authdir]/?tok=[token]&redir=[landing_page_url]`

 This is most commonly achieved using an html form of method GET.
 The parameter redir can be the client's originally requested URL sent by NDS, or more usefully, the URL of a suitable landing page.

 Be aware that many client CPD processes will **automatically close** the landing page as soon as Internet access is detected.

BinAuth Post FAS Processing
***************************

As BinAuth can be enabled at the same time as FAS, a BinAuth script may be used for custom post FAS processing. (see BinAuth).

Manual Access of NDS Virtual URL
********************************

If the user of an already authenticated client device manually accesses the NDS Virtual URL, they will be redirected back to FAS with the "status" query string.

 This will be of the form:

 `http://fasremoteip:fasport/faspath?clientip=[clientip]&gatewayname=[gatewayname]&status=authenticated`

FAS should then serve a suitable error page informing the client user that they are already logged in.

Running FAS on your Nodogsplash router
**************************************

FAS has been tested using uhttpd, lighttpd, ngnix, apache and libmicrohttpd.

**Running on OpenWrt with uhttpd/PHP**:

 A FAS service may run quite well on uhttpd (the web server that serves Luci) on an OpenWrt supported device with 8MB flash and 32MB ram but shortage of ram will be an issue if more than two or three clients log in at the same time.

 For this reason a device with a minimum of 8MB flash and 64MB ram is recommended.

 *Although port 80 is the default for uhttpd, it is reserved for Captive Portal Detection so cannot be used for FAS. uhttpd can however be configured to operate on more than one port.*

 We will use port 2080 in this example.

 Install the module php7-cgi. Further modules may be required depending on your requirements.

 To enable FAS with php in uhttpd you must add the lines:

  ``list listen_http	0.0.0.0:2080``

  ``list interpreter ".php=/usr/bin/php-cgi"``

 to the /etc/config/uhttpd file in the config uhttpd 'main' or first section.

 The two important NDS options to set will be:

 1. fasport. We will use port 2080 for uhttpd

 2. faspath. Set to, for example, /myfas/fas.php,
    your FAS files being placed in /www/myfas/

Using a Shared Hosting Server for a Remote FAS
**********************************************

 A typical Internet hosted **shared** server will be set up to serve multiple domain names.

 To access yours, it is important to configure the two options:

  fasremoteip = the **ip address** of the remote server

  **AND**

  fasremotefqdn = the **Fully Qualified Domain name** of the remote server

Using the FAS Example Script
****************************

You can run the FAS example script locally on the same OpenWrt device that is running NDS (A minimum of 64MB of ram may be enough, but 128MB is recommended).

Assuming you have installed your web server of choice, configured it for port 2080 and added PHP support using the package php7-cgi, you can do the following.

 (Under other operating systems you may need to edit the nodogsplash.conf file in /etc/nodogsplash instead, but the process is very similar.)

 * Install the packages php7-cli and php7-mod-openssl

 * Create a folder /[server-web-root]/nds/

 * Place the file fas-aes.php in /[server-web-root]/nds/

   (You can find it in the /etc/nodogsplash directory.)

 * Edit the file /etc/config/nodogsplash

  adding the lines:

    ``option fasport '2080'``

    ``option faspath '/nds/fas-aes.php'``

    ``option fas_secure_enabled '2'``

    ``option faskey '1234567890'``

 * Restart NDS using the command "service nodogsplash restart".

Changing faskey
***************

The value of option faskey should of course be changed, but must also be pre-shared with FAS by editing the example or your own script to match the new value.


