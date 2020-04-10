How NoDogSplash (NDS) works
###########################

NoDogSplash is a Captive Portal Engine. Any Captive Portal, including NDS, will have two main components:

 * Something that does the capturing, and
 * Something to provide a Portal for client users to log in.

NoDogSplash MUST run on a device configured as an IPv4 router.

A wireless router will typically be running OpenWrt or some other Linux distribution.

A router, by definition, will have two or more interfaces, at least one to connect to the wide area network (WAN) or Internet feed, and at least one connecting to the local area network (LAN).

Each LAN interface must also act as the Default IP Gateway for its LAN, ideally with the interface serving IP addresses to client devices using DHCP.

Multiple LAN interfaces can be combined into a single bridge interface. For example, ethernet, 2.4Ghz and 5Ghz networks are typically combined into a single bridge interface. Logical interface names will be assigned such as eth0, wlan0, wlan1 etc. with the combined bridge interface named as br-lan.

NDS will manage one or more of them of them. This will typically be br-lan, the bridge to both the wireless and wired LAN, but could be, for example, wlan0 if you wanted NDS to work just on the wireless interface.

Summary of Operation
********************

By default, NDS blocks everything, but intercepts port 80 requests.

An initial port 80 request will be generated on a client device, usually automatically by the client device's built in Captive Portal Detection (CPD), or possibly by the user manually browsing to an http web page.

This request will of course **be routed by the client device to the Default Gateway** of the local network. The Default Gateway will, as we have seen, be the router interface that NDS is managing.

The Thing That Does the Capturing (NDS)
=======================================

 As soon as this initial port 80 request is received on the default gateway interface, NDS will "Capture" it, make a note of the client device identity, allocate a unique token for the client device, then redirect the client browser to the Portal component of NDS.

The Thing That Provides the Portal (the Splash page)
====================================================

 The client browser is redirected to the Portal component. This is a web service that is configured to know how to communicate with the core engine of NDS.

 This is commonly known as the Splash Page.

 NDS has its own web server built in and this is used to serve the Portal "Splash" page to the client browser.

 NDS comes with a standard Splash Page pre-installed.

 This is a trivial Click to Continue splash page with template variables.

 Once the user on the client device has successfully completed the splash page actions, that page then links directly back to NDS.

 For security, NDS expects to receive the same valid token it allocated when the client issued its initial port 80 request. If the token received is valid, NDS then "authenticates" the client device, allowing access to the Internet.

Captive Portal Detection (CPD)
******************************

All modern mobile devices, most desktop operating systems and most browsers now have a CPD process that automatically issues a port 80 request on connection to a network. NDS detects this and serves a special “splash” web page to the connecting client device.

The port 80 html request made by the client CPD can be one of many vendor specific URLs.

    Typical CPD URLs used are, for example:

    * `http://captive.apple.com/hotspot-detect.html`
    * `http://connectivitycheck.gstatic.com/generate_204`
    * `http://connectivitycheck.platform.hicloud.com/generate_204`
    * `http://www.samsung.com/`
    * `http://detectportal.firefox.com/success.txt`
    *  Plus many more

It is important to remember that CPD is designed primarily for mobile devices to automatically detect the presence of a portal and to trigger the login page, without having to resort to breaking SSL/TLS security by requiring the portal to redirect port 443 for example.

Just about all current CPD implementations work very well but some compromises are necessary depending on the application.

The vast majority of devices attaching to a typical Captive Portal are mobile devices. CPD works well giving the initial login page.

For a typical guest wifi, eg a coffee shop, bar, club, hotel etc., a device connects, the Internet is accessed for a while, then the user takes the device out of range.

When taken out of range, a typical mobile device begins periodically polling the wireless spectrum for SSIDs that it knows about to try to obtain a connection again, subject to timeouts to preserve battery life.

Most Captive Portals have a session duration limit (NDS included).

If a previously logged in device returns to within the coverage of the portal, the previously used SSID is recognised and CPD is triggered and tests for an Internet connection in the normal way. Within the session duration limit of the portal, the Internet connection will be established, if the session has expired, the splash page will be displayed again.

Early mobile device implementations of CPD used to poll their detection URL at regular intervals, typically around 30 to 300 seconds. This would trigger the Portal splash page quite quickly if the device stayed in range and the session limit had been reached. 

However it was very quickly realised that this polling kept the WiFi on the device enabled continuously having a very negative effect on battery life, so this polling whilst connected was either increased to a very long interval or removed all together (depending on vendor) to preserve battery charge. As most mobile devices come and go into and out of range, this is not an issue.

A common issue raised is:

*My devices show the splash page when they first connect, but when the authorization expires, they just announce there is no internet connection. I have to make them "forget" the wireless network to see the splash page again. Is this how is it supposed to work?*

The workaround is as described in the issue, or even just manually disconnecting or turning WiFi off and on will simulate a "going out of range", initialising an immediate trigger of the CPD. One or any combination of these workarounds should work, again depending on the particular vendor's implementation of CPD.

In contrast, most laptop/desktop operating systems, and browser versions for these still implement CPD polling whilst online as battery considerations are not so important.

For example, Gnome desktop has its own built in CPD browser with a default interval of 300 seconds. Firefox also defaults to something like 300 seconds. Windows 10 is similar.

This IS how it is supposed to work, but does involve some compromises.

The best solution is to set the session timeout to a value greater than the expected length of time a client device is likely to be present. Experience shows a limit of 24 hours covers most situations eg bars, clubs, coffee shops, motels etc. If for example an hotel has guests regularly staying for a few days, then increase the session timeout as required.

Packet filtering
****************

Nodogsplash considers four kinds of packets coming into the router over the managed interface. Each packet is one of these kinds:

 1. **Blocked**, if the MAC mechanism is block, and the source MAC address of the packet matches one listed in the BlockedMACList; or if the MAC mechanism is allow, and source MAC address of the packet does not match one listed in the AllowedMACList or the TrustedMACList. These packets are dropped.
 2. **Trusted**, if the source MAC address of the packet matches one listed in the TrustedMACList. By default, these packets are accepted and routed to all destination addresses and ports. If desired, this behavior can be customized by FirewallRuleSet trusted-users and FirewallRuleSet trusted-users-to-router lists in the nodogsplash.conf configuration file, or by the EmptyRuleSetPolicy trusted-users EmptyRuleSetPolicy trusted-users-to-router directives.
 3. **Authenticated**, if the packet's IP and MAC source addresses have gone through the nodogsplash authentication process and has not yet expired. These packets are accepted and routed to a limited set of addresses and ports (see FirewallRuleSet authenticated-users and FirewallRuleSet users-to-router in the nodogsplash.conf configuration file).
 4. **Preauthenticated**. Any other packet. These packets are accepted and routed to a limited set of addresses and ports (see FirewallRuleSet      preauthenticated-users and FirewallRuleSet users-to-router in the nodogsplash.conf configuration file). Any other packet is dropped, except that a packet for destination port 80 at any address is redirected to port 2050 on the router, where nodogsplash's built in libhttpd-based web server is listening. This begins the 'authentication' process. The server will serve a splash page back to the source IP address of the packet. The user clicking the appropriate link on the splash page will complete the process, causing future packets from this IP/MAC address to be marked as Authenticated until the inactive or forced timeout is reached, and its packets revert to being Preauthenticated.


NoDogSplash implements these actions by inserting rules in the router's iptables mangle PREROUTING chain to mark packets, and by inserting rules in the nat PREROUTING, filter INPUT and filter FORWARD chains which match on those marks.

Because it inserts its rules at the beginning of existing chains, NoDogSplash should be insensitive to most typical existing firewall configurations.

Traffic control
***************

Data rate control on an IP connection basis can be achieved using Smart Queue Management (SQM) configured separately, with NDS being fully compatible.

It should be noted that while setup options and BinAuth do accept traffic/quota settings, these values currently have no effect and are reserved for future development.
