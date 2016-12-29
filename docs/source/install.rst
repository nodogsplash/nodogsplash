Installing nodogsplash
######################

OpenWrt
*******

* Have a router working with OpenWrt. Nodogsplash has been compiled against a
  OpenWrt Attitude Adjustment buildroot; it may or may not work on other versions
  of OpenWrt or on other kinds of Linux-based router firmware. For notes on
  using Nodogsplash with OpenWrt Kamikaze, see below.
* Make sure your router is basically working before you try to install
  nodogsplash. In particular, make sure your DHCP daemon is serving addresses
  on the interface that nodogsplash will manage (typically br-lan or eth1), and
  for the following use ssh or telnet access to your router over a different
  interface.
* To install nodogsplash, obtain the nodogsplash*.ipk package you want to
  install from the project website, copy it to /tmp/ on your OpenWrt router,
  and, in as root on the router, run:

  ``opkg install /tmp/nodogsplash*.ipk``

  (Note: to prevent installation of an older package, you may have to remove
  references to remote package repositories in your /etc/opkg.conf file)
* If the interface that you want nodogsplash to manage is not br-lan,
  edit /etc/nodogsplash/nodogsplash.conf and set GatewayInterface.
* To start nodogsplash, run the following, or just reboot the router:

    ``/etc/init.d/nodogsplash start``

* To test the installation, connect a client machine to the interface on your
  router that is managed by nodogsplash (for example, connect to the router's
  wireless lan) and in a browser on that machine, attempt to visit any website.
  You should see the nodogsplash splash page instead. Click on the icon; the
  browser should redirect to the initially requested website.
* To stop nodogsplash:

    ``/etc/init.d/nodogsplash stop``

* To uninstall nodogsplash:

    ``opkg remove nodogsplash``

Debian
******

There isn't a packet in the repostiory (yet). But we have support for a debian package.
Requirements beside debian tools are:

- libmicrohttpd-dev (>= 0.9.51) [avaiable in **stretch**]

But you can also compile libmicrohttpd on your own if you're still running jessie or older.


``sudo apt-get install debhelper dpkg-dev dh-systemd libmicrohttpd-dev``


.. code::

   apt-get install build-essential debhelper devscripts hardening-includes

Run this command in the repository root folder to create the package:

.. code::

   dpkg-buildpackage

The package will be created in the parent directory.


Use this command if you want to create an unsigned package:

.. code::

   dpkg-buildpackage -b -rfakeroot -us -uc

You will find the .deb packages in parent directory.
