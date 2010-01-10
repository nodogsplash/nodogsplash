#
# $Id: Makefile.am 901 2006-01-17 18:58:13Z mina $
#

lib_LTLIBRARIES = libhttpd.la

libhttpd_la_SOURCES = protocol.c \
	api.c \
	version.c \
	ip_acl.c

noinst_HEADERS = httpd_priv.h

pkginclude_HEADERS = httpd.h

EXTRA_DIST = README

#AM_CPPFLAGS = \
#	-I${top_srcdir}/inc

clean-local:
	echo "clean-local: " && pwd
	rm -f *~
