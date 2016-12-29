How nodogsplash works
#####################

A wireless router running OpenWrt has two or more interfaces; nodogsplash
manages one of them. This will typically be br-lan, the bridge to both the
wireless and wired LAN; or the wireless lan interface may be named something
else if you have broken the br-lan bridge to separate the wired and wireless
LAN's.

Packet filtering
****************

Nodogsplash considers four kinds of packets coming into the router over the
managed interface. Each packet is one of these kinds:

  1. Blocked, if the MAC mechanism is block, and the source MAC address of the
     packet matches one listed in the BlockedMACList; or if the MAC mechanism
     is allow, and source MAC address of the packet does not match one listed
     in the AllowedMACList or the TrustedMACList. These packets are dropped.
  2. Trusted, if the source MAC address of the packet matches one listed in the
     TrustedMACList. By default, these packets are accepted and routed to all
     destination addresses and ports. If desired, this behavior can be
     customized by FirewallRuleSet trusted-users and FirewallRuleSet trusted-
     users-to-router lists in the nodogsplash.conf configuration file, or by
     the EmptyRuleSetPolicy trusted-users EmptyRuleSetPolicy trusted-users-to-
     router directives.
  3. Authenticated, if the packet's IP and MAC source addresses have gone
     through the nodogsplash authentication process and has not yet expired.
     These packets are accepted and routed to a limited set of addresses and
     ports (see FirewallRuleSet authenticated-users and FirewallRuleSet users-
     to-router in the nodogsplash.conf configuration file).
  4. Preauthenticated. Any other packet. These packets are accepted and routed
     to a limited set of addresses and ports (see FirewallRuleSet
     preauthenticated-users and FirewallRuleSet users-to-router in the
     nodogsplash.conf configuration file). Any other packet is dropped, except
     that a packet for destination port 80 at any address is redirected to port
     2050 on the router, where nodogsplash's builtin libhttpd-based web server
     is listening. This begins the 'authentication' process. The server will
     serve a splash page back to the source IP address of the packet. The user
     clicking the appropriate link on the splash page will complete the
     process, causing future packets from this IP/MAC address to be marked as
     Authenticated until the inactive or forced timeout is reached, and its
     packets revert to being Preauthenticated.

Nodogsplash implements these actions by inserting rules in the router's
iptables mangle PREROUTING chain to mark packets, and by inserting rules in the
nat PREROUTING, filter INPUT and filter FORWARD chains which match on those
marks. Because it inserts its rules at the beginning of existing chains,
nodogsplash should be insensitive to most typical existing firewall
configurations.

Traffic control
***************

Nodogsplash also optionally implements basic traffic control on its managed
interface. This feature lets you specify the maximum aggregate upload and
download bandwidth that can be taken by clients connected on that interface.
Nodogsplash implements this functionality by enabling two intermediate queue
devices (IMQ's), one for upload and one for download, and attaching simple
rate-limited HTB qdiscs to them. Rules are inserted in the router's iptables
mangle PREROUTING and POSTROUTING tables to jump to these IMQ's. The result is
simple but effective tail-drop rate limiting (no packet classification or
fairness queueing is done).

.. note::
   IMQ is not included anymore by OpenWrt Attitude Adjustment (12.09).
