# $Id: Makefile.am 935 2006-02-01 03:22:04Z benoitg $

SUBDIRS = libhttpd src . doc 

docdir = ${prefix}/share/doc/nodogsplash-@VERSION@

doc_DATA = \
  AUTHORS \
  COPYING \
  INSTALL \
  README \
  ChangeLog

EXTRA_DIST = \
  FAQ \
  nodogsplash.spec.in \
  nodogsplash.spec \
  config \
  scripts \
  debian/rules \
  debian/control \
  debian/changelog \
  ipkg/rules \
  nodogsplash.conf

.PHONY: doc
doc:
	$(MAKE) -C doc doc

.PHONY: ipkg
ipkg: all
	./ipkg/rules BUILDROOT=$(BUILDROOT)

.PHONY: rpm
rpm: dist
	cp ${builddir}nodogsplash.spec /usr/src/RPM/SPECS
	cp ${builddir}nodogsplash-@VERSION@.tar.gz /usr/src/RPM/SOURCES
	rpmbuild -ta ${builddir}nodogsplash-@VERSION@.tar.gz

clean-local:
	echo "clean-local: " && pwd
	rm -f *~

