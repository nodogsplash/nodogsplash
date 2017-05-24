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

This feature is broken since OpenWrt 12.09 (Attitude Adjustment), because
OpenWrt removed the IMQ (Intermediate queueing device) support. We're looking
for somebody who want to fix that.

Is https:// redirection supported?
**********************************

No. We believe this is the wrong way to do it, because all connection would have a critical certificate failure.
As certain network managers evolved on major Operating Systems (Linux, Android, iOS/macOS, Windows),
the network manager will detect the presence of a hotspot and notify the user.
