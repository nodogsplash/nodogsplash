PreAuth Option
=================

Overview
********

PreAuth is a means to provide a Forwarding Authentication Service (FAS) for Nodogsplash (NDS) utilising NDS's built in web server.

PreAuth is a means of serving dynamic html using the built in NDS web server.

This means a FAS can be implemented without the resource utilisation of a separate web server, particularly useful for legacy devices with limited flash and RAM capacity.

To use PreAuth, NDS FAS configuration is set to point to a virtual URL in the NDS web root instead of an external FAS server. In addition, NDS is configured with the location of the PreAuth script or program.

The PreAuth script can be a shell script or any other script type that an interpreter is available for (for example, PHP-cli, Python etc.).

It could also be, for example, a compiled program written in C or any other language that has a compiler available for the platform.

The PreAuth script or program will parse the url encoded command line (query string) passed to it and output html depending on the contents of the query string it receives from NDS. In turn, NDS will serve this html to the client device that is attempting to access the Internet.


Using PreAuth
*************
PreAuth is set up using the standard NDS configuration for FAS
(See the **Forwarding Authentication Service (FAS)** section of this documentation).

In addition a single PreAuth configuration option is required to inform NDS of the location of the PreAuth script or program.

In summary, the following configuration options should be set:
 1. **fasport**. This enables FAS and *must* be set to the same value as the gateway port.
 2. **faspath**. This *must* be set to the PreAuth virtual url, "/nodogsplash_preauth/" by default.

The remaining FAS configuration options must be left unset at the default values.

ie:
 1. **fasremoteip**. Not set (defaults to the gateway ip address).
 2. **fas_secure_enable**. Not set (defaults to enabled).

**Finally** the Preauth configuration must be set.
In OpenWrt this will be of the form
option preauth /etc/nodogsplash/demo-preauth.sh
For other Linux distributions this is set in the nodogsplash.conf file.

Using The Example PreAuth Script
********************************

An example PreAuth script is provided along with the FAS examples and should be copied to a convenient location on your router eg "/etc/nodogsplash/", remembering to flag as executable.

This example shell script generates html output for NDS to serve as a dynamic splash page.

It asks the client user to enter their name and email address.
On entering this information the client user then clicks or taps "Continue".

The script then generates html code to send to NDS to serve a second "Thankyou" page and creates a log entry ( /tmp/ndslog.log ), recording the client authentication details.

On tapping "Continue" for the second time, the client user is given access to the Internet.

This is a simple example of a script to demonstrate how to use PreAuth as a built in FAS. The script could of course ask for any response from the client and conduct its own authentication procedures - entirely at the discretion of the person setting up their own captive portal functionality.

Writing A Preauth Script
************************

A Preauth script can be written as a shell script or any other language that the system has an interpreter for. It could also be a complied program.

NDS calls the preauth script with a command line equivalent to an html query string but with ", " (comma space) in place of "&" (ampersand).

Full details are included in the example script demo-preauth.sh available by downloading the Nodogsplash zip file from

 `https://github.com/nodogsplash/nodogsplash/`

and extracting from the folder 

 "forward_authentication_service/PreAuth/"

Defining and Using Variables
****************************

The query string is sent to us from NDS in a urlencoded form, so we must decode it here so we can parse it. In a shell script we would use the code:

 `query=$(printf "${query_enc//%/\\x}")`

In the example script we want to ask the client user for their username and email address.

We could ask for anything we like and add our own variables to the html forms we generate.

If we want to show a sequence of forms or information pages we can do this easily.

To return to the script and show additional pages, the form action must be set to:

 `<form action=\"/nodogsplash_preauth/\" method=\"get\">`

Note: quotes ( " ) must be escaped with the "\" character.

Any variables we need to preserve and pass back to ourselves or NDS must be added to the form as hidden:

 `<input type=\"hidden\" name=......`

Such variables will appear in the query string when NDS re-calls this script.

We can then parse for them again.

When the logic of this script decides we should allow the client to access the Internet we inform NDS with a final page displaying a continue button with the form action set to:

 `"<form action=\"/nodogsplash_auth/\" method=\"get\">"`

We must also send NDS the client token as a hidden variable, but first we must obtain the token from ndsctl using a suitable command such as:

 `tok="$(ndsctl json $clientip | grep token | cut -c 10- | cut -c -8)"`

In a similar manner we can obtain any client or NDS information that ndsctl provides.

The query string NDS sends to us will always be of the following form (with a "comma space" separator):

 `?clientip=[clientipaddress], gatewayname=[gatewayname],  redir=[originalurl], var4=[data], var5=[data], var6......`

The first three variables will be clientip, gatewayname and redir

We have chosen to name redir as $requested here as it is actually the originally requested url.

There is one exception to this. If the client presses "back" on their browser NDS detects this and tells us by returning status=authenticated instead of redir=[originalurl]

If we detect this we show a page telling the client they are already logged in.

Additional variables returned by NDS will be those we define here and send to NDS via an html form method=get

See the example script which uses $username and $emailaddr

There is no limit to the number of variables we can define dynamically as long as the query string does not exceed 2048 bytes.

The query string will be truncated if it does exceed this length.
