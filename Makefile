
CC?=gcc
CFLAGS?=-O2
CFLAGS+=-Isrc -Ilibhttpd
#CFLAGS+=-Wall -Wwrite-strings -pedantic -std=gnu99
LDFLAGS+=-pthread
LDLIBS=

NDS_OBJS=src/auth.o src/client_list.o src/commandline.o src/conf.o \
	src/debug.o src/firewall.o src/fw_iptables.o src/gateway.o src/http.o \
	src/httpd_thread.o src/ndsctl_thread.o src/safe.o src/tc.o src/util.o

LIBHTTPD_OBJS=libhttpd/api.o libhttpd/ip_acl.o \
	libhttpd/protocol.o libhttpd/version.o

.PHONY: all clean install checkastyle fixstyle

all: nodogsplash ndsctl

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

nodogsplash: $(NDS_OBJS) $(LIBHTTPD_OBJS)
	$(CC) $(LDFLAGS) -o nodogsplash $+ $(LDLIBS)

ndsctl: src/ndsctl.o
	$(CC) $(LDFLAGS) -o ndsctl $+ $(LDLIBS)

clean:
	rm -f nodogsplash ndsctl src/*.o libhttpd/*.o
	rm -rf dist

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

checkastyle:
	@command -v astyle >/dev/null 2>&1 || \
	{ echo >&2 "We need 'astyle' but it's not installed. Aborting."; exit 1; }

fixstyle: checkastyle
	@echo "\033[1;34mChecking style ...\033[00m"
	@astyle --lineend=linux --suffix=none --style=kr --indent=force-tab \
	--formatted --recursive "src/*.c" "src/*.h"|grep formatted \
	&& echo "\033[1;33mPrevious files have been corrected\033[00m" \
	|| echo "\033[0;32mAll files are ok\033[00m"

deb:
	mkdir -p dist/nodogsplash/
	cd dist/nodogsplash/; \
		cp -rp ../../debian/ .; \
		ln -s ../../Makefile;\
		ln -s ../../src;\
		ln -s ../../libhttpd;\
		ln -s ../../resources;\
		dpkg-buildpackage -b -us -uc
	rm -rf dist/nodogsplash
