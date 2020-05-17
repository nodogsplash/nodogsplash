
CC?=gcc
CFLAGS?=-O2 -g -Wall
CFLAGS+=-Isrc
#CFLAGS+=-Wall -Wwrite-strings -pedantic -std=gnu99
LDFLAGS+=-pthread
LDLIBS=-lmicrohttpd

STRIP=yes

NDS_OBJS=src/auth.o src/client_list.o src/commandline.o src/conf.o \
	src/debug.o src/fw_iptables.o src/path.o src/main.o src/http_microhttpd.o src/http_microhttpd_utils.o \
	src/ndsctl_thread.o src/safe.o src/tc.o src/util.o src/template.o

.PHONY: all clean install checkastyle fixstyle deb

all: nodogsplash ndsctl

%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

nodogsplash: $(NDS_OBJS) $(LIBHTTPD_OBJS)
	$(CC) $(LDFLAGS) -o nodogsplash $+ $(LDLIBS)

ndsctl: src/ndsctl.o
	$(CC) $(LDFLAGS) -o ndsctl $+ $(LDLIBS)

clean:
	rm -f nodogsplash ndsctl src/*.o
	rm -rf dist

install:
#ifeq(yes,$(STRIP))
	strip nodogsplash
	strip ndsctl
#endif
	mkdir -p $(DESTDIR)/usr/bin/
	cp ndsctl $(DESTDIR)/usr/bin/
	cp nodogsplash $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/etc/nodogsplash/htdocs/images
	cp resources/nodogsplash.conf $(DESTDIR)/etc/nodogsplash/
	cp resources/splash.html $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/splash.css $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/status.html $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/splash.jpg $(DESTDIR)/etc/nodogsplash/htdocs/images/

checkastyle:
	@command -v astyle >/dev/null 2>&1 || \
	{ echo >&2 "We need 'astyle' but it's not installed. Aborting."; exit 1; }

checkstyle: checkastyle
	@if astyle \
		--dry-run \
		--lineend=linux \
		--suffix=none \
		--style=kr \
		--indent=force-tab \
		--formatted --recursive "src/*.c" "src/*.h" | grep -q -i formatted ; then \
			echo Please fix formatting or run fixstyle ; false ; else \
			echo Style looks ok. ; fi

fixstyle: checkastyle
	@echo "\033[1;34mChecking style ...\033[00m"
	@if astyle \
		--dry-run \
		--lineend=linux \
		--suffix=none \
		--style=kr \
		--indent=force-tab \
		--formatted --recursive "src/*.c" "src/*.h" | grep -q -i formatted ; then \
			echo "\033[1;33mPrevious files have been corrected\033[00m" ; else \
			echo "\033[0;32mAll files are ok\033[00m" ; fi

DEBVERSION=$(shell dpkg-parsechangelog | awk -F'[ -]' '/^Version/{print($$2); exit;}' )
deb: clean
	mkdir -p dist/nodogsplash-$(DEBVERSION)
	tar --exclude dist --exclude ".git*" -cf - . | (cd dist/nodogsplash-$(DEBVERSION) && tar xf -)
	cd dist && tar cjf nodogsplash_$(DEBVERSION).orig.tar.bz2 nodogsplash-$(DEBVERSION) && cd -
	cd dist/nodogsplash-$(DEBVERSION) && dpkg-buildpackage -us -uc && cd -
	rm -rf dist/nodogsplash-$(DEBVERSION)
