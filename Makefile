
CC?=gcc
CFLAGS?=-O2
CFLAGS+=-Isrc -Ilibhttpd
#CFLAGS+=-Wall -Wwrite-strings -pedantic -std=gnu99
LDFLAGS+=-pthread
LDLIBS=

NDS_OBJS=src/auth.o src/client_list.o src/commandline.o src/conf.o \
	src/debug.o src/firewall.o src/fw_iptables.o src/gateway.o src/http.o \
	src/httpd_handler.o src/ndsctl_thread.o src/safe.o src/tc.o src/util.o

LIBHTTPD_OBJS=libhttpd/api.o libhttpd/ip_acl.o \
	libhttpd/protocol.o libhttpd/version.o

.PHONY: all clean install

all: nodogsplash ndsctl

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

nodogsplash: $(NDS_OBJS) $(LIBHTTPD_OBJS)
	$(CC) $(LDFLAGS) -o nodogsplash $+ $(LDLIBS)

ndsctl: src/ndsctl.o
	$(CC) $(LDFLAGS) -o ndsctl $+ $(LDLIBS)

clean:
	rm -f nodogsplash ndsctl src/*.o libhttpd/*.o

install:
	strip nodogsplash
	strip ndsctl
	mkdir -p $(DESTDIR)/usr/bin/
	cp ndsctl $(DESTDIR)/usr/bin/
	cp nodogsplash $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/etc/nodogsplash/htdocs/images
	cp resources/nodogsplash.conf $(DESTDIR)/etc/nodogsplash/
	cp resources/splash.html $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/infoskel.html $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/splash.jpg $(DESTDIR)/etc/nodogsplash/htdocs/images/
