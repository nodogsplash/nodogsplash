How to compile Nodogsplash
##########################

Linux/Unix
**********

Install libmicrohttpd including the header files (often call -dev package).

.. code::

   git clone https://github.com/nodogsplash/nodogsplash.git
   cd nodogsplash
   make

If you installed the libmicrohttpd to another location (e.g. /tmp/libmicrohttpd_install/)
replace path in the make call with

.. code::

   make CFLAGS="-I/tmp/libmicrohttpd_install/include" LDFLAGS="-L/tmp/libmicrohttpd_install/lib"

After compiling you can call ``make install`` to install nodogsplash to /usr/

OpenWrt
*******

To compile nodogsplash please use the package definition from the feeds package.

.. code::

   git clone git://git.openwrt.org/trunk/openwrt.git
   cd openwrt
   ./scripts/feeds update
   ./scripts/feeds install
   ./scripts/feeds install nodogsplash

Select the appropriate "Target System" and "Target Profile" in the menuconfig menu and build the image.

.. code::

   make defconfig
   make menuconfig
   make
