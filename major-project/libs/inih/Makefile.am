AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = ini.h cpp/INIReader.h

AM_CFLAGS = ${CFLAGS} -fPIC -DPIC
AM_CXXFLAGS = ${CXXFLAGS} -fPIC -DPIC

noinst_LTLIBRARIES = libini.la libinic.la

libini_la_SOURCES = ini.c cpp/INIReader.cpp
libini_la_CFLAGS = ${AM_CFLAGS}
libini_la_CXXFLAGS = ${AM_CXXFLAGS}
libini_la_LDFLAGS = -static

libinic_la_SOURCES = ini.c
libinic_la_CFLAGS = ${AM_CFLAGS}
libinic_la_CXXFLAGS = ${AM_CXXFLAGS}
libinic_la_LDFLAGS = -static

