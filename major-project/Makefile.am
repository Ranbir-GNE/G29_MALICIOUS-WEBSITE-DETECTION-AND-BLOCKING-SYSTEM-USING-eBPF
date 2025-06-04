# Netify Agent Top-Level Automake File
# Copyright (C) 2016-2024 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

DEBUG_HOST := root@gw.sokoloski.ca

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS_EXTRA =
if USE_LIBTCMALLOC_BUNDLED
SUBDIRS_EXTRA += libs/gperftools
endif

SUBDIRS = libs/inih libs/ndpi $(SUBDIRS_EXTRA) include src deploy doc tests util
DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = LICENSE VERSION autogen.sh debian/compat util libs/gperftools

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) \
	--with-tmpfilesdir=$$dc_install_base/$(tmpfilesdir)

pkgconfig_DATA = lib@PACKAGE_TARNAME@.pc

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(volatilestatedir)
	$(MKDIR_P) $(DESTDIR)$(persistentstatedir)/categories.d
	$(MKDIR_P) $(DESTDIR)$(persistentstatedir)/plugins.d

uninstall-local:
	rmdir $(DESTDIR)$(volatilestatedir)
	rmdir $(DESTDIR)$(persistentstatedir)/categories.d
	rmdir $(DESTDIR)$(persistentstatedir)/plugins.d

netifyd-CentOS_8.spec: netifyd.spec
	grep -v 'gperftools-devel' netifyd.spec > netifyd-CentOS_8.spec

deploy-rpm:
	$(MAKE) dist-gzip
	cp -v $(PACKAGE)-$(VERSION).tar.gz ~/rpmbuild/SOURCES/
	rpmbuild -ba $(PACKAGE).spec

deploy-debug: all
	rsync -av --progress --inplace src/.libs/netifyd $(DEBUG_HOST):/usr/sbin/
	rsync -avl --progress --inplace src/.libs/libnetifyd.so* $(DEBUG_HOST):/usr/lib64/

deploy-debug-archive: all
	mkdir -p /tmp/netifyd-debug/usr/{sbin,lib64}
	cp src/.libs/netifyd /tmp/netifyd-debug/usr/sbin/
	cp src/.libs/libnetifyd.so.0.0.0 /tmp/netifyd-debug/usr/lib64/
	cd /tmp/netifyd-debug && tar -cvzf ../netifyd-debug.tar.gz *

include $(abs_top_srcdir)/automake/dist-git.am
