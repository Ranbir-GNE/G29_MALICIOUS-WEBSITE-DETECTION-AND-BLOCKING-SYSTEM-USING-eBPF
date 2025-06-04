# Netify Agent Tests Automake File
# Copyright (C) 2016-2020 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

TEMPLATES = netifyd-test-pcap.conf
TEMPLATES_IN = netifyd-test-pcap.conf.in

BUILT_SOURCES = $(TEMPLATES)
CLEANFILES = $(TEMPLATES)
EXTRA_DIST = ndpi-pcap-files.txt netifyd-test-pcap.conf \
	test-pcap-logs test-pcap-regression.sh pcap/ssdp.cap.gz \
	$(TEMPLATES_IN)

%: %.in
	$(SED) \
		-e 's|[@]testdir@|$(abs_builddir)/netifyd|g' \
		< "$<" > "$@"

clean-local:
	rm -f $(TEMPLATES)

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I $(top_srcdir)/include \
	-I $(top_srcdir)/libs/ndpi/src/include -I $(top_srcdir)/libs/inih/cpp \
	$(LIBCURL_CFLAGS) $(ZLIB_CFLAGS) \
	-D_ND_INTERNAL=1 \
	-D'ND_CONF_FILE_NAME="$(sysconfdir)/$(PACKAGE_TARNAME).conf"' \
	-D'ND_DATADIR="$(datadir)/$(PACKAGE_TARNAME)"' \
	-D'ND_PERSISTENT_STATEDIR="$(persistentstatedir)"' \
	-D'ND_PID_FILE_NAME="$(volatilestatedir)/$(PACKAGE_TARNAME).pid"' \
	-D'ND_VOLATILE_STATEDIR="$(volatilestatedir)"'

if USE_LIBTCMALLOC
AM_CPPFLAGS += $(LIBTCMALLOC_CFLAGS)
endif

if USE_CONNTRACK
AM_CPPFLAGS += $(LIBNETFILTER_CONNTRACK_CFLAGS) $(LIBMNL_CFLAGS)
endif

bin_PROGRAMS = check-protocols check-risks

check_protocols_SOURCES = check-protocols.cpp
check_protocols_LDADD = $(top_srcdir)/src/libnetifyd.la $(top_srcdir)/libs/inih/libini.la $(LIBCURL_LIBS) $(ZLIB_LIBS)

if USE_LIBTCMALLOC
# XXX: Recommended compiler flags
AM_CPPFLAGS += $(LIBTCMALLOC_CFLAGS) -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
# XXX: It's important that this library be linked after all others.
check_protocols_LDADD += $(LIBTCMALLOC_LIBS)
endif

check_risks_SOURCES = check-risks.cpp
check_risks_LDADD = $(top_srcdir)/src/libnetifyd.la $(top_srcdir)/libs/inih/libini.la $(LIBCURL_LIBS) $(ZLIB_LIBS)

if USE_LIBTCMALLOC
# XXX: Recommended compiler flags
AM_CPPFLAGS += $(LIBTCMALLOC_CFLAGS) -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
# XXX: It's important that this library be linked after all others.
check_risks_LDADD += $(LIBTCMALLOC_LIBS)
endif

dirs:
	$(MKDIR_P) \
		"$(abs_builddir)/netifyd/var/run/netifyd" \
		"$(abs_builddir)/netifyd/etc/netifyd/plugins.d" \
		"$(abs_builddir)/netifyd/etc/netifyd/categories.d" \
		"$(abs_builddir)/netifyd/etc/netifyd/interfaces.d"

test: dirs
	sudo WITH_VALGRIND="no" TESTDIR="$(abs_builddir)" ./test-pcap-regression.sh

test-valgrind: dirs
	sudo WITH_VALGRIND="yes" TESTDIR="$(abs_builddir)" ./test-pcap-regression.sh

clean-local: clean-local-check
clean-local-check:
	-rm -rf pcap-test/*.cap

.PHONY: test clean-local-check
