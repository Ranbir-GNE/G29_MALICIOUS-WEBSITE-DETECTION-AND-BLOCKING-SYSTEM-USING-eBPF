# Netify Agent Include Automake File
# Copyright (C) 2016-2024 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

TEMPLATEFILES = nd-version.hpp
TEMPLATEFILES_IN = nd-version.hpp.in

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)
EXTRA_DIST = nlohmann pcap-compat radix $(TEMPLATEFILES_IN)

netifyincludedir = $(includedir)/netifyd
netifyinclude_HEADERS = nd-addr.hpp nd-apps.hpp nd-base64.hpp nd-capture.hpp \
	nd-capture-nfq.hpp nd-capture-pcap.hpp nd-capture-tpv3.hpp nd-category.hpp \
	nd-config.hpp nd-conntrack.hpp nd-detection.hpp nd-dhc.hpp nd-except.hpp \
	nd-fhc.hpp nd-flags.hpp nd-flow.hpp nd-flow-map.hpp nd-flow-parser.h \
	nd-flow-parser.hpp nd-instance.hpp nd-napi.hpp nd-ndpi.hpp nd-netlink.hpp \
	nd-packet.hpp nd-plugin.hpp nd-progress.hpp nd-protos.hpp nd-risks.hpp \
	nd-serializer.hpp nd-sha1.h nd-signal.hpp nd-thread.hpp nd-tls-alpn.hpp \
	nd-util.hpp nd-version.hpp netifyd.hpp

nlohmannincludedir = $(includedir)/netifyd/nlohmann
nlohmanninclude_HEADERS = nlohmann/json.hpp

pcapcompatincludedir = $(includedir)/netifyd/pcap-compat
pcapcompatinclude_HEADERS = pcap-compat/sll.h pcap-compat/vlan.h

radixincludedir = $(includedir)/netifyd/radix
radixinclude_HEADERS = radix/radix_tree.hpp radix/radix_tree_it.hpp \
	radix/radix_tree_node.hpp

%: %.in
	$(SED) \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]ND_VERSION@|$(ND_VERSION)|g' \
		< "$<" > "$@"
