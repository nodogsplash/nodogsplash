Frequently Asked Questions
###########################

Can I update from v0.9/v1/v2/v3/v4 to v5?
*****************************************

You can, if:

* You only want a simple templated splash page
* You have iptables v1.4.21 or above

**From version 5.0.0 onwards**, NoDogSplash is optimised for minimum non volatile storage (flash) and RAM requirements.

The advanced API support provided by BinAuth, Preauth and FAS have been moved to the **openNDS** package:
https://opennds.readthedocs.io

How do I use QoS or Traffic Control on OpenWrt?
***********************************************

The original pre version 1 feature has been broken since OpenWrt 12.09 (Attitude Adjustment), because the IMQ (Intermediate queueing device) is no longer supported.

 **Pull Requests are welcome!**

 However the OpenWrt package, SQM Scripts (Smart Queue Management), is fully compatible with Nodogsplash and if configured to operate on the NoDogSplash interface (br-lan by default) will provide efficient IP connection based traffic control to ensure fair usage of available bandwidth.

Is https capture supported?
***************************
**No**. Because all connections would have a critical certificate failure.

 HTTPS web sites are now more or less a standard and to maintain security and user confidence it is essential that captive portals **DO NOT** attempt to capture port 443.

What is CPD / Captive Portal Detection?
***************************************
CPD (Captive Portal Detection) has evolved as an enhancement to the network manager component included with major Operating Systems (Linux, Android, iOS/macOS, Windows).

 Using a pre-defined port 80 web page (which one gets used depends on the vendor) the network manager will detect the presence of a captive portal hotspot and notify the user. In addition, most major browsers now support CPD.

**It should be noted** when designing a custom splash page that for security reasons many client device CPD implementations:

 * Immediately close the browser when the client has authenticated.

 * Prohibit the use of href links.

 * Prohibit downloading of external files (including .css and .js, even if they are allowed in NDS firewall settings).

 * Prohibit the execution of javascript.
