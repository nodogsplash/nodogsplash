Traffic Control
###############

Overview
********

Nodogsplash (NDS) supports Traffic Control (Bandwidth Limiting) using the SQM - Smart Queue Management (sqm-scripts) package, available for OpenWrt and generic Linux.

https://github.com/tohojo/sqm-scripts

SQM does efficient bandwidth control, independently for both upload and download, on an IP connection basis. This ideal for enforcing a fair usage policy on a typical Captive Portal implementation.

In addition the Queue management SQM provides, results in significantly improved WiFi performance, particularly on the modern low cost WiFi routers available on the market today.

Finally, SQM controls quality of service (QOS), allowing priority for real time protocols such a VOIP.

Overall, SQM can enhance significantly the experience of clients using your Captive Portal, whilst ensuring a single client is unlikely to dominate the available Internet service at the expense of others.

Installing SQM
**************
The generic Linux scripts can be downloaded from the link above.

**On OpenWrt**, SQM can be installed from the LuCi interface or by the following CLI commands on your router:

`opkg update`

`opkg install sqm-scripts`

**Note**:
The standard and default SQM installation expects monitoring of the interface connecting to the WAN. What we need is for SQM to monitor the interface NDS is bound to. This of course will be a LAN interface.
The default configuration will limit bandwidth from the WAN connection to services on the Internet. Our configuration will limit client bandwidth TO NDS, thus enabling a true fair usage policy.

*To prevent confusion* it is important to understand that SQM defines "Upload" as traffic "Out" of the interface SQM is monitoring and "Download" as traffic "In" to the SQM interface.

In the default SQM configuration, Upload will mean what is normally accepted, ie traffic to the Internet and Download will mean traffic from the Internet.

**In our case however the terms will be reversed!**

The default SQM configuration file on OpenWrt is:

.. code-block:: sh

 config queue
     option enabled '0'
     option interface 'eth1'
     option download '85000'
     option upload '10000'
     option qdisc 'fq_codel'
     option script 'simple.qos'
     option qdisc_advanced '0
     option ingress_ecn 'ECN'
     option egress_ecn 'ECN'
     option qdisc_really_really_advanced '0'
     option itarget 'auto'
     option etarget 'auto'
     option linklayer 'none'

For simple rate limiting, we are interested in setting the desired interface and the download/upload rates. 

We may also want to optimize for the type of Internet feed and change the qdisc.

A typical Internet feed could range from a high speed fiber optic connection through fast VDSL to a fairly poor ADSL connection and configured rates should be carefully chosen when setting up your Captive Portal.

A typical Captive Portal however will be providing free Internet access to customers and guests at a business or venue, using their mobile devices.

A good compromise for a business or venue might be a download rate from the Internet of ~3000 Kb/s and an upload rate to the Internet of ~1000 Kb/s will be adequate, allowing for example, a client to stream a YouTube video, yet have minimal effect on other clients browsing the Internet or downloading their emails. Obviously the values for upload and download rates for best overall performance depend on many factors and are best determined by trial and error.

If we assume we have NDS bound to interface br-lan and we have a VDSL connection, a good working setup for SQM will be as follows:

 * *Rate to* Internet 1000 Kb/s (but note this is from the perspective of the interface SQM is monitoring, so this means DOWNLOAD from the client).
 * *Rate from* Internet 3000 Kb/s (also note this is from the perspective of the interface SQM is monitoring, so is means UPLOAD to the client).
 * *VDSL* connection (usually an ethernet like connection)
 * *NDS* bound to br-lan

We will configure this by issuing the following commands:

*Note the reversed "upload" and "download" values.*

.. code-block:: sh

    uci set sqm.@queue[0].interface='br-lan'

    uci set sqm.@queue[0].download='1000'

    uci set sqm.@queue[0].upload='3000'

    uci set sqm.@queue[0].linklayer='ethernet'

    uci set sqm.@queue[0].overhead='22'

    uci set sqm.@queue[0].qdisc='cake'

    uci set sqm.@queue[0].script='piece_of_cake.qos'

    uci set sqm.@queue[0].enabled='1'

    uci commit sqm

    service sqm restart


Replace the linklayer and overhead values to match your Internet feed.

The following table lists LinkLayer types and Overhead for common feed types:

 ================   ========== =========
 Connection Type    LinkLayer  Overhead
 ================   ========== =========
 Fibre/Cable        Ethernet   18
 VDSL2              Ethernet   22
 Ethernet           Ethernet   38
 ADSL/DSL           ATM        44
 ================   ========== =========

Some broadband providers use variations on the values shown here, contacting them for details sometimes helps but often the request will be "off script" for a typical helpdesk. These table values should give good results regardless. Trial and error and the use of a good speed tester is often the only way forward.
A good speed tester web site is http://dslreports.com/speedtest

Further details about SQM can be found at the following links:

https://openwrt.org/docs/guide-user/network/traffic-shaping/sqm

https://openwrt.org/docs/guide-user/network/traffic-shaping/sqm-details

