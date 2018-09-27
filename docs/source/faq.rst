Frequently Asked Questions
###########################

What's the difference between v0.9, v1, v2 and v3?
**************************************************

v0.9 and v1 are the same codebase with the same feature set.
If the documentation says something about v1, this is usually also valid
for v0.9.

v2 was developed before version v1 was released. In v2 the http code was replaced by libmicrohttpd and the template engine was rewritten. Many features became defunct because of this procedure.

v3 cleans up the source code and adds two major new features,

 FAS enabling an external forwarding authentication service to be called,

 and 

 binauth, enabling an external script to be called for simple username/password authentication as well as doing post authentication processing such as setting session durations. This is similar to the old binvoucher feature, but more flexible.

In addition, in v3, the ClientTimeout setting was split into PreauthIdleTimeout and AuthIdleTimeout and for the ClientForceTimeout setting, SessionTimeout is now used instead.

Can I update from v0.9 to v1
****************************

Updating to v1.0.0 and v1.0.1, this is a very smooth update with full compatibility.

Updating to 1.0.2 requires iptables v1.4.21 or above.

Can I update from v0.9/v1 to v2.0.0
***********************************

You can, if:

* You don't use BinVoucher
* You have iptables v1.4.21 or above


Can I update from v0.9/v1/v2 to v3.0.0
**************************************

You can, if:

* You don't use BinVoucher
* You have iptables v1.4.21 or above
* You use the new options contained in the version 3 configuration file

I would like to use QoS or TrafficControl on OpenWrt
****************************************************

The original pre version 1 feature has been broken since OpenWrt 12.09 (Attitude Adjustment), because the IMQ (Intermediate queueing device) is no longer supported.

 **Pull Requests are welcome!**

However the OpenWrt package, SQM Scripts (Smart Queue Management), is fully compatible with Nodogsplash and if configured to operate on the Nodogsplash interface (br-lan by default) will provide efficient IP connection based traffic control to ensure fair usage of available bandwidth.

Is https capture supported?
******************************

**No**. Because all connections would have a critical certificate failure.

HTTPS web sites are now more or less a standard and to maintain security and user confidence it is essential that captive portals **DO NOT** attempt to capture port 443.

**Captive Portal Detection** (CPD) has evolved as an enhancement to the network manager component included with major Operating Systems (Linux, Android, iOS/macOS, Windows). Using a pre-defined port 80 web page (depending on the vendor) the network manager will detect the presence of a captive portal hotspot and notify the user. In addition, most major browsers now support CPD.
