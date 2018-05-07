Frequenctly Asked Questions
###########################

What's the difference between v0.9, v1 and v2?
**********************************************

v0.9 and v1 are the same codebase with the same feature set.
If the documentation says something about v1, this is usally also valid
for v0.9.

v2 was developed while version v1 wasn't released. In v2 the http code got replaced by libmicrohttpd
as well the template engine got rewritten.

Can I update from v0.9 to v1
****************************

This is a very smooth update with full compatibility.

Can I update from v0.9/v1 to v2.0.0
***********************************

You can, if you don't use:

* BinVoucher (there is a `PR#144 <https://github.com/nodogsplash/nodogsplash/pull/144>`_)

I would like to use QoS or TrafficControl on OpenWrt
****************************************************

The original pre version 1 feature has been broken since OpenWrt 12.09 (Attitude Adjustment), because
OpenWrt removed the IMQ (Intermediate queueing device) support. We're looking for somebody who to fix this!

However the OpenWrt package, SQM Scripts, is fully compatible with Nodogsplash and if configured to operate on the Nodogsplash interface (br-lan by default) will provide efficient IP connection based traffic control to ensure fair usage of available bandwidth.

Is https:// redirection supported?
**********************************

No. We believe this is the wrong way to do it, because all connections would have a critical certificate failure.
Https web sites are now more or less a standard and to maintain security and user confidence it is essential that captive portals DO NOT attempt to capture port 443.

Captive Portal Detection (CPD) has evolved as an enhancement to the network manager component included with major Operating Systems (Linux, Android, iOS/macOS, Windows). Using a pre defined port 80 web page (depending on the vendor) the network manager will detect the presence of a captive portal hotspot and notify the user. In addition, most major browsers now support CPD.
