Installing NoDogSplash
######################

OpenWrt
*******

* Have a router working with OpenWrt. At the time of writing, Nodogsplash has been tested with OpenWrt 18.06.x, 19.7.x and Snapshot.

* It may or may not work on older versions of OpenWrt or on other kinds of Linux-based router firmware.

* Make sure your router is basically working before you try to install  NoDogSplash. In particular, make sure your DHCP daemon is serving addresses on the interface that NoDogSplash will manage.

  The default is br-lan but can be changed to any interface by editing the /etc/config/nodogsplash file.

* To install Nodogsplash, you may use the OpenWrt Luci web interface or alternatively, ssh to your router and run the command:

    ``opkg update``

  followed by

    ``opkg install nodogsplash``

* NoDogSplash is enabled by default and will start automatically on reboot or can be started and stopped manually.

* If the interface that you want NoDogSplash to manage is not br-lan,
  edit /etc/config/nodogsplash and set GatewayInterface.

* To start NoDogSplash, run the following, or just reboot the router:

    ``service nodogsplash start``

* To test the installation, connect a client device to the interface on your router that is managed by NoDogSplash (for example, connect to the router's wireless lan).

 Most client device operating systems and browsers support Captive Portal Detection (CPD) and the operating system or browser on that device will attempt to contact a pre defined port 80 web page.

 CPD will trigger NoDogSplash to serve the default splash page where you can click or tap Continue to access the Internet.

 See the Authentication section for details of setting up a proper authentication process.

 If your client device does not display the splash page it most likely does not support CPD.

 You should then manually trigger NoDogSplash by trying to access a port 80 web site (for example, google.com:80 is a good choice).

* To stop NoDogSplash:

    ``service nodogsplash stop``

* To uninstall NoDogSplash:

    ``opkg remove nodogsplash``

Debian
******

There isn't a package in the repository (yet). But we have support for a Debian package.

Requirements beside Debian tools are:

- libmicrohttpd-dev (>= 0.9.51) [avaiable in **stretch**]

But you can also compile libmicrohttpd your self if you're still running jessie or older.

To compile NoDogSplash and create the Debian package, see the chapter "How to Compile NoDogSplash".