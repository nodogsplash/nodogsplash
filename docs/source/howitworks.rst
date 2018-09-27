How Nodogsplash (NDS) works
###########################

A wireless router, typically running OpenWrt or some other Linux distribution, has two or more interfaces; NDS manages one of them. This will typically be br-lan, the bridge to both the wireless and wired LAN; or could be for example wlan0 if you wanted NDS to work just on the wireless interface.

**A simplified summary of operation is as follows**:

 By default, NDS blocks everything, but intercepts port 80 requests.

 An initial port 80 request will be generated on a client device, either by the user manually browsing to an http web page, or automatically by the client device's built in Captive Portal Detection (CPD).

 As soon as this initial port 80 request is received, NDS will redirect the client to either its own splash page, or a splash page on a configured Forwarding Authentication Service (FAS).

 The user of the client device will then be expected to complete some actions on the splash page, such as accepting terms of service, entering a username and password etc. (this will of course be on either the basic NDS splash.html or the page presented by the FAS, depending on the NDS configuration).

 Once the user on the client device has successfully completed the splash page actions, the page then links directly, with a query string, to an NDS virtual http directory provided by NDS's built in web server.

 For security, NDS expects to receive the same valid token it allocated when the client issued its initial port 80 request. If the token received is valid, NDS then "authenticates" the client device, allowing access to the Internet.

 However if Binauth is enabled, NDS first calls the Binauth script, passing if required a username and password to that script.

 If the binauth script returns positively (ie return code 0), NDS then "authenticates" the client device, allowing access to the Internet.

 In FAS secure mode, it is the responsibility of the FAS to obtain the client token in a secure manner from NDS.

 When FAS is disabled, the token is supplied to the basic splash.html page served by NDS and passed back in clear text in the query string along with any username and password required for Binauth.

.. note::

 FAS and Binauth can be enabled together.
 This can give great flexibility with FAS providing authentication     and Binauth providing post authentication processing closely linked to  NDS.

Packet filtering
****************

Nodogsplash considers four kinds of packets coming into the router over the managed interface. Each packet is one of these kinds:

 1. **Blocked**, if the MAC mechanism is block, and the source MAC address of the packet matches one listed in the BlockedMACList; or if the MAC mechanism is allow, and source MAC address of the packet does not match one listed in the AllowedMACList or the TrustedMACList. These packets are dropped.
 2. **Trusted**, if the source MAC address of the packet matches one listed in the TrustedMACList. By default, these packets are accepted and routed to all destination addresses and ports. If desired, this behavior can be customized by FirewallRuleSet trusted-users and FirewallRuleSet trusted-users-to-router lists in the nodogsplash.conf configuration file, or by the EmptyRuleSetPolicy trusted-users EmptyRuleSetPolicy trusted-users-to-router directives.
 3. **Authenticated**, if the packet's IP and MAC source addresses have gone through the nodogsplash authentication process and has not yet expired. These packets are accepted and routed to a limited set of addresses and ports (see FirewallRuleSet authenticated-users and FirewallRuleSet users-to-router in the nodogsplash.conf configuration file).
 4. **Preauthenticated**. Any other packet. These packets are accepted and routed to a limited set of addresses and ports (see FirewallRuleSet      preauthenticated-users and FirewallRuleSet users-to-router in the nodogsplash.conf configuration file). Any other packet is dropped, except that a packet for destination port 80 at any address is redirected to port 2050 on the router, where nodogsplash's built in libhttpd-based web server is listening. This begins the 'authentication' process. The server will serve a splash page back to the source IP address of the packet. The user clicking the appropriate link on the splash page will complete the process, causing future packets from this IP/MAC address to be marked as Authenticated until the inactive or forced timeout is reached, and its packets revert to being Preauthenticated.


 Nodogsplash implements these actions by inserting rules in the router's iptables mangle PREROUTING chain to mark packets, and by inserting rules in the nat PREROUTING, filter INPUT and filter FORWARD chains which match on those marks.

 Because it inserts its rules at the beginning of existing chains, nodogsplash should be insensitive to most typical existing firewall configurations.

Traffic control
***************

Data rate control on an IP connection basis can be achieved using Smart Queue Management (SQM) configured separately, with NDS being fully compatible.

It should be noted that while setup options and binauth do accept traffic/quota settings, these values currently have no effect and are reserved for future development.
