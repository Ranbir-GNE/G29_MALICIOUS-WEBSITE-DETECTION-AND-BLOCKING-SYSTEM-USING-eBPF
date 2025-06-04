# Netify Agent Deploy Automake File
# Copyright (C) 2016-2024 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

SUBDIRS = debian systemd

TEMPLATEFILES = functions.sh netifyd.conf netifyd.init
TEMPLATEFILES_IN = functions.sh.in netifyd.conf.in netifyd.init.in

sharedatadir = $(datadir)/netifyd
sharedata_DATA = functions.sh netify-apps.conf netify-proc-core-auto.json \
	netify-sink-http-auto.json

sysconf_DATA = netifyd.conf

persistentstate_DATA = netify-apps.conf netify-categories.json

interfacesdir = $(persistentstatedir)/interfaces.d
interfaces_DATA = ./interfaces.d/10-example-nfq.conf \
	./interfaces.d/10-example-tpv3.conf ./interfaces.d/10-example-pcap.conf

autopluginsdir = $(datadir)/netifyd/plugins.d
autoplugins_DATA = ./plugins.d/99-netify-proc-core-auto.conf \
	./plugins.d/99-netify-sink-http-auto.conf

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)
EXTRA_DIST = $(TEMPLATEFILES_IN) freebsd netifyd.default netify-apps.conf netify-categories.json

%: %.in
	$(SED) \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]libdir@|$(libdir)|g' \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sharedatadir@|$(sharedatadir)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]persistentstatedir@|$(persistentstatedir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"

install-data-hook:
	-chmod a+x $(DESTDIR)$(sharedatadir)/*.sh
