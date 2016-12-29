#!/bin/bash
# builds and install libmicrohttp to /tmp/libmicrohttp_install
#
# this script is intended for test environments like travis.
# it only takes arguments via environment

# used env:
# MHD_VERSION - which version to install - has a default value

# exit immediately if a command exits with a non-zero status.
set -e

if [ $# -ne 1 -o "$1" != "--compile"  ] ; then
	echo "This script is intended for test systems. See source code for more information." >&2
	echo "$# $1"
	exit 1
fi

if [ -z "$MHD_VERSION" ] ; then
	MHD_VERSION="0.9.51"
fi
unset CFLAGS
rm -rf /tmp/libmicrohttpd*
wget http://ftpmirror.gnu.org/libmicrohttpd/libmicrohttpd-${MHD_VERSION}.tar.gz -O /tmp/mhd_src.tar.gz
tar zxf /tmp/mhd_src.tar.gz -C /tmp/
mv /tmp/libmicrohttpd-* /tmp/libmicrohttpd
mkdir /tmp/libmicrohttpd_install
cd /tmp/libmicrohttpd
./configure --without-openssl --without-gnutls --disable-spdy --disable-https --prefix /tmp/libmicrohttpd_install
make -j2
make install
