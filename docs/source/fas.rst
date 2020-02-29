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
 5. **fas_secure_enable**. This can have four values, "0", "1", "2" or "3" providing different levels of security.
 6. **faskey** Used in combination with fas_secure_enable level 1, 2 and 3, this is a key phrase for NDS to encrypt data sent to FAS.
 
.. note::
 FAS (and Preauth/FAS) enables pre authentication processing. NDS authentication is the process that NDS uses to allow a client device to access the Internet through the Firewall. In contrast, Forward Authentication is a process of "Credential Verification", after which FAS, if the verification process is successful, passes the client token to NDS for access to the Internet to be granted.

Using FAS
*********

**Note**:
All addresses (with the exception of fasremoteip) are relative to the *client* device, even if the FAS is located remotely.

When FAS is enabled, NDS automatically configures firewall access to the FAS service.

The FAS service must serve a splash page of its own to replace the NDS splash.html. For fas_secure_enable "0", "1", and "2" this is enforced as http. For fas_secure_enable level "3", it is enforced as https.

Typically, the FAS service will be written in PHP or any other language that can provide dynamic web content.

FAS can then provide an action form for the client, typically requesting login, or self account creation for login.

The FAS can be on the same device as NDS, on the same local area network as NDS, or on an Internet hosted web server.

Security
********

**If FAS Secure is enabled** (Levels 1 (default), 2 and 3), the client authentication token is kept secret until FAS verification is complete.

   **If set to "0"** The FAS is enforced by NDS to use **http** protocol.
   The client token is sent to the FAS in clear text in the query string of the redirect along with authaction and redir.

   **If set to "1"** The FAS is enforced by NDS to use **http** protocol.
   When the sha256sum command is available AND faskey is set, the client token will be hashed and sent to the FAS identified as "hid" in the query string. The gatewayaddress is also sent on the query string, allowing the FAS to construct the authaction parameter. FAS must return the sha256sum of the concatenation of the original hid and faskey to be used by NDS for client authentication. This is returned in the normal way in the query string identified as "tok". NDS will automatically detect whether hid mode is active or the raw token is being returned.

   Should sha256sum not be available or faskey is not set, then it is the responsibility of the FAS to request the token from NDSCTL.

   **If set to "2"** The FAS is enforced by NDS to use **http** protocol.

   clientip, clientmac, gatewayname, client token, gatewayaddress, authdir, originurl and clientif are encrypted using faskey and passed to FAS in the query string.

   The query string will also contain a randomly generated initialization vector to be used by the FAS for decryption.

   The cipher used is "AES-256-CBC".

   The "php-cli" package and the "php-openssl" module must both be installed for fas_secure level 2.

   Nodogsplash does not depend on this package and module, but will exit gracefully if this package and module are not installed when this level is set.

   The FAS must use the query string passed initialisation vector and the pre shared fas_key to decrypt the query string. An example FAS level 2 php script (fas-aes.php) is preinstalled in the /etc/nodogsplash directory and also supplied in the source code.

   **If set to "3"** The FAS is enforced by NDS to use **https** protocol.
   Level 3 is the same as level 2 except the use of https protocol is enforced for FAS. In addition, the "authmon" daemon is loaded. This allows the external FAS, after client verification, to effectively traverse inbound firewalls and address translation to achieve NDS authentication without generating browser security warnings or errors. An example FAS level 3 php script (fas-aes-https.php) is preinstalled in the /etc/nodogsplash directory and also supplied in the source code.

**Option faskey must be set** if fas secure is set to levels 2 and 3 but is optional for level 1.

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

  **If faskey is set**, NDS sends a digest of the random client token:

  `http://fasremotefqdn:fasport/faspath?hid=[hash_id]&gatewayname=[gatewayname]&clientip=[clientip]&redir=[requested-url]`

   The FAS must return the hash of the concatenated hid value and the value of faskey identified in the query string as "tok". NDS will automatically detect this.

  **If faskey is not set** the following is sent:

  `http://fasremotefqdn:fasport/faspath?gatewayname=[gatewayname]&clientip=[clientip]&redir=[requested-url]`

   It is the responsibility of FAS to obtain the unique client token allocated by NDS as well as constructing the return URL to NDS.

   The return url will be constructed by FAS from predetermined knowledge of the configuration of NDS using gatewayname as an identifier.

   The client's unique access token will be obtained from NDS by the FAS making a call to the get_client_token library utility:

   ``/usr/lib/nodogsplash/./get_client_token $clientip``

   A json parser could be used to extract all the client variables supplied by ndsctl, an example can be found in the default PreAuth Login script in /usr/lib/nogogsplash/login.sh.

  **Levels 2 and 3** (fas_secure_enabled = 2 and fas_secure_enabled = 3), NDS sends encrypted information to FAS.

  `http://fasremotefqdn:fasport/faspath?fas=[aes-256-cbc data]&iv=[random initialisation vector]` (level 2)

  `https://fasremotefqdn:fasport/faspath?fas=[aes-256-cbc data]&iv=[random initialisation vector]` (level 3)

   It is the responsibility of FAS to decrypt the aes-256-cbc data it receives, using the pre shared faskey and the random initialisation vector.

  The decrypted string received by FAS will be of the form:
  [varname1]=[var1], [varname2]=[var2], ..... etc. (the separator being comma-space).

  eg `clientip=192.168.8.23, clientmac=04:15:52:6a:e4:ad, tok=770bfe05, originurl=.....`

  Variables sent by NDS in the encrypted string in NDS v4.0.0 and above are as follows:

  **clientip clientmac gatewayname tok gatewayaddress authdir originurl clientif**

  Where:
   **tok** is the client token

   **gatewayaddress** is authentication address of NDS ie [nds_ip]:[nds_port]

   **authdir** is the NDS virtual authentication directory

   **clientif** is the interface string identifying the interface the client is connected to in the form of:
    [local interface] [meshnode mac] [local mesh interface]


  Future versions of NDS may send additional variables and the order of the variables in the decrypted string may also vary, so it is the responsiblity of FAS to parse the decrypted string for the variables it requires.

Network Zones - Determining the Interface the Client is Connected To
********************************************************************

The Network coverage of a Captive Portal can take many forms, from a single SSID through to an extensive mesh network.

Using FAS, it is quite simple to dynamically adapt the Client Login page depending on the Network Zone a client is connected to.
NDS can determine the local interface or 802.11s mesh network node a client is using. A simple lookup table can then be included in a custom FAS, relating interfaces or mesh nodes to sensibly named coverage zones.

A very simple example would be a captive portal set up with a wireless network for "Staff", another for "Guests" and office machines connected via ethernet.

 * Ethernet connected office machines would gain access by simply clicking "Continue".
 * Staff mobiles connect to the Staff WiFi using a standard access code then clicking "Continue".
 * Guests connect to the open Guest Wifi and are required to enter details such as Name, email address etc.

NDS is aware of the interface or mesh node a client is using.

For a FAS using `fas_secure_enabled = 2`, an additional variable, clientif, is sent to the FAS in the encrypted query string (local or remote FAS).

For all other levels of fas_secure_enabled, PreAuth and BinAuth, the library utility "get_client_interface" is required to be used by the relevant script (local FAS only).

Working examples can be found in the included scripts:

 * fas-aes.php
 * login.sh
 * demo-preauth.sh
 * demo-preauth-remote-image.sh

For details of the clientif variable and how to use get_client_interface, see the section **Library Utilities**.

After Successful Verification by FAS
************************************

If the client is successfully verified by the FAS, FAS will return the unique token, or its hashed equivalent to NDS to finally allow the client access to the Internet.

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


