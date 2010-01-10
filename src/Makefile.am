#
# Based on Wifidog Makefile.am by benoitg
#

bin_PROGRAMS = nodogsplash \
	ndsctl

AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"' 
nodogsplash_LDADD = $(top_builddir)/libhttpd/libhttpd.la

nodogsplash_SOURCES = commandline.c \
	conf.c \
	debug.c \
	fw_iptables.c \
	firewall.c \
	gateway.c \
	http.c \
	auth.c \
	client_list.c \
	util.c \
	ndsctl_thread.c \
	safe.c \
	httpd_thread.c \
	tc.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	fw_iptables.h \
	firewall.h \
	gateway.h \
	http.h \
	auth.h \
	client_list.h \
	util.h \
	ndsctl_thread.h \
	ndsctl.h \
	safe.h \
	httpd_thread.h \
	tc.h

ndsctl_SOURCES = ndsctl.c

clean-local:
	echo "clean-local: " && pwd
	rm -f *~
