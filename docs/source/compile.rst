How to compile Nodogsplash
##########################

Linux/Unix
**********

Install libmicrohttpd including the header files (often call -dev package).

.. code::

   git clone https://github.com/nodogsplash/nodogsplash.git
   cd nodogsplash
   make

If you installed the libmicrohttpd to another location please like /tmp/libmicrohttpd_install/
replace the make call with

.. code::

   make CFLAGS="-I/tmp/libmicrohttpd_install/include" LDFLAGS="-L/tmp/libmicrohttpd_install/lib"

After compiling you can call ``make install`` to install nodogsplash to /usr/

OpenWrt
*******

To compile nodogsplash please ues the package definiton from the feeds package.

.. code::

   cd openwrt
   ./scripts/feeds update
   ./scripts/feeds install nodogsplash
