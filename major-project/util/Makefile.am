# Netify Agent Tests Automake File
# Copyright (C) 2016-2020 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

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

bin_PROGRAMS = risks-to-csv

risks_to_csv_SOURCES = risks-to-csv.cpp
risks_to_csv_LDADD = $(top_srcdir)/src/libnetifyd.la $(top_srcdir)/libs/inih/libini.la $(LIBCURL_LIBS) $(ZLIB_LIBS)

if USE_LIBTCMALLOC
# XXX: Recommended compiler flags
AM_CPPFLAGS += $(LIBTCMALLOC_CFLAGS) -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
# XXX: It's important that this library be linked after all others.
risks_to_csv_LDADD += $(LIBTCMALLOC_LIBS)
endif
