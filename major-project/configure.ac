# Netify Agent Autoconf configuration

m4_include([m4/ax_pkg_installdir.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
m4_include([m4/ax_git_vars.m4])
m4_include([m4/ax_check_progs.m4])

AC_PREREQ([2.72])
AC_INIT([Netify Agent],[m4_esyscmd_s([head -n 1 VERSION])],[https://gitlab.com/netify.ai/public/netify-agent/issues],[netifyd],[https://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([src/netifyd.cpp])
AC_CONFIG_SUBDIRS([libs/inih libs/ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([_ND_HOST_CPU], ["${host_cpu}"], [Defines the canonical host.])
AC_DEFINE_UNQUOTED([_ND_HOST_OS], ["${host_os}"], [Defines the canonical host OS.])

# Library version
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
m4_define([lnv_current], [4])
m4_define([lnv_revision], [0])
m4_define([lnv_age], [0])
lt_version="lnv_current:lnv_revision:lnv_age"
AC_SUBST([LIBNETIFY_VERSION], [$lt_version])

# Shared object filename: (CURRENT - AGE).AGE.REVISION
m4_define([lnv_so], m4_eval(lnv_current - lnv_age))
#m4_define([lnv_so], [m4_eval([lnv_current] - [lnv_age])])
so_version="so.lnv_so"
AC_SUBST([LIBNETIFY_VERSION_SO], [$so_version])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LEX([yywrap])
AC_PROG_YACC
AC_PROG_EGREP
AC_CHECK_TOOL([STRIP], [strip])
LT_INIT
PKG_PROG_PKG_CONFIG([0.23])
AX_PKG_INSTALLDIR
AX_CHECK_PROGS

# Defines we will pass to pkg-config:
ND_DEFINES=""

# Check compiler flags
AX_CXX_COMPILE_STDCXX_11
AS_VAR_APPEND([CXXFLAGS], [" -std=gnu++11"])

# Checks for libraries.
AC_CHECK_LIB([pthread],
    [pthread_create], [], [AC_MSG_ERROR([libpthread/pthread_create() not found.])])
AC_CHECK_LIB([dl],
    [dlopen], [], [AC_MSG_ERROR([libdl/dlopen() not found.])])
AC_CHECK_LIB([rt],
    [timer_create], [], [AC_MSG_ERROR([librt/timer_create() not found.])])

AC_CHECK_LIB([bpf], [bpf_map_create], [
    AC_CHECK_LIB([bpf], [bpf_object__open_mem])
    AC_CHECK_LIB([bpf], [bpf_object__load])
    AC_CHECK_LIB([bpf], [bpf_object__find_map_by_name])
    AC_CHECK_LIB([bpf], [bpf_object__find_map_fd_by_name])
    AC_CHECK_LIB([bpf], [bpf_map_update_elem])
    AC_CHECK_LIB([bpf], [bpf_map__fd])
    AC_CHECK_LIB([bpf], [bpf_object__find_program_by_name])
    AC_CHECK_LIB([bpf], [bpf_program__fd])
    AC_CHECK_LIB([bpf], [bpf_link_create])
    AC_CHECK_LIB([bpf], [bpf_map_update_elem])
    AC_CHECK_LIB([bpf], [remove_bpf_map_entry])
    AC_CHECK_LIB([bpf], [bpf_map_delete_elem])
    AC_DEFINE([_ND_ENABLE_LIBBPF], [1], [Define if libbpf is available.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_LIBBPF=1"])
    LIBS="$LIBS -lbpf -lmysqlcppconn"
], [
    AC_MSG_ERROR([libbpf not found.])
])

AC_CHECK_LIB([atomic], [__atomic_load_8])

AC_CHECK_LIB([pcap], [pcap_open_live])
AC_CHECK_FUNC([pcap_open_dead], [
    AC_DEFINE([HAVE_PCAP_OPEN_DEAD], [1], [Define if pcap_open_dead is available.])
])

AS_IF([test "$ac_cv_lib_pcap_pcap_open_live" = "yes"], [
    AC_DEFINE([_ND_ENABLE_LIBPCAP], [1], [Define if libpcap is available.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_LIBPCAP=1"])
    AM_CONDITIONAL(USE_LIBPCAP, true)
], [
    AM_CONDITIONAL(USE_LIBPCAP, false)
])

AC_MSG_CHECKING([for DLT_* macros in pcap/bpf.h])
AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([
        #include <pcap/bpf.h>
    ], [
        #ifndef DLT_EN10MB
        #error "DLT_EN10MB not defined"
        #endif
    ])
], [
    AC_MSG_RESULT([no])
], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_ND_PCAP_DLT_IN_BPF_H], [1], [Define if DLT_* macros are defined in pcap/bpf.h.])
])

case "${host_os}" in
    linux*)
        AC_CHECK_LIB([resolv],
            [ns_initparse], [], [AC_MSG_ERROR([libresolv/ns_initparse() not found.])])

        dnl CONNTRACK support

        AC_ARG_ENABLE([conntrack],
            [AS_HELP_STRING([--enable-conntrack], [Enable connection tracking support [default=yes]])],
            [],
            [enable_conntrack=yes])

        AS_IF([test "x$enable_conntrack" = "xyes"], [
            AC_DEFINE([_ND_ENABLE_CONNTRACK], [1],
                [Define to enable connection tracking support.])
            PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
            PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.4])
            AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_CONNTRACK=1"])
            AM_CONDITIONAL(USE_CONNTRACK, true)
        ], [
            AM_CONDITIONAL(USE_CONNTRACK, false)
        ])

        dnl CONNTRACK meta-data extraction support

        AC_ARG_ENABLE([conntrack-mdata],
            [AS_HELP_STRING([--enable-conntrack-mdata], [Enable connection tracking metadata [default=no]])],
            [],
            [enable_conntrack_mdata=no])

        AS_IF([test "x$enable_conntrack_mdata" = "xyes"], [
            AC_DEFINE([_ND_ENABLE_CONNTRACK_MDATA], [1],
                [Enable to extract additional conntrack metadata (ID and mark).])
            AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_CONNTRACK_MDATA=1"])
        ])

        dnl NETLINK support

        AC_ARG_ENABLE([netlink],
            [AS_HELP_STRING([--enable-netlink], [Enable Netlink socket support [default=yes]])],
            [],
            [enable_netlink=yes])

        AS_IF([test "x$enable_netlink" = "xyes"], [
            AC_DEFINE([_ND_ENABLE_NETLINK], [1],
                [Define to enable Netlink socket support.])
            AM_CONDITIONAL(USE_NETLINK, true)
            AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_NETLINK=1"])
        ], [
            AM_CONDITIONAL(USE_NETLINK, false)
        ])

        dnl TPACKETv3 Capture Support

        AC_ARG_ENABLE([tpacketv3],
            [AS_HELP_STRING([--enable-tpacketv3], [Enable TPACKETv3 capture support [default=yes]])],
            [],
            [enable_tpacketv3=yes])

        AS_IF([test "x$enable_tpacketv3" = "xyes"], [
            AC_CHECK_HEADERS([linux/if_packet.h], [],
                AC_MSG_ERROR([linux/if_packet.h header(s) not found.])
            )
            AC_DEFINE([_ND_ENABLE_TPACKETV3], [1],
                [Define to enable TPACKETv3 capture support.])
            AM_CONDITIONAL(USE_TPACKETV3, true)
            AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_TPACKETV3=1"])
        ], [
            AM_CONDITIONAL(USE_TPACKETV3, false)
        ])

        dnl NFQUEUE Capture Support

        AC_ARG_ENABLE([nfqueue],
            [AS_HELP_STRING([--enable-nfqueue], [Enable NFQUEUE capture support [default=no]])],
            [],
            [enable_nfqueue=no])

        AS_IF([test "x$enable_nfqueue" = "xyes"], [
            PKG_CHECK_MODULES([LIBNETFILTER_QUEUE], [libnetfilter_queue >= 1.0.4])
            AC_DEFINE([_ND_ENABLE_NFQUEUE], [1],
                [Define to enable NFQUEUE capture support.])
            AM_CONDITIONAL(USE_NFQUEUE, true)
            AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_NFQUEUE=1"])
        ], [
            AM_CONDITIONAL(USE_NFQUEUE, false)
        ])
        ;;

    *)
        AM_CONDITIONAL(USE_CONNTRACK, false)
        AM_CONDITIONAL(USE_NETLINK, false)
        AM_CONDITIONAL(USE_NFQUEUE, false)
        AM_CONDITIONAL(USE_TPACKETV3, false)
        ;;
esac

PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([ZLIB], [zlib])

# Parameters: --with/without
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])

AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])

AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_ARG_WITH([tmpfilesdir],
     [AS_HELP_STRING([--with-tmpfilesdir=DIR], [Directory for systemd tmpfiles configuration])],,
     [with_tmpfilesdir=auto])

AS_IF([test "x$with_tmpfilesdir" = "xyes" -o "x$with_tmpfilesdir" = "xauto"], [
     def_tmpfilesdir=$($PKG_CONFIG --variable=tmpfilesdir systemd)
     AS_IF([test "x$def_tmpfilesdir" = "x"],
   [AS_IF([test "x$with_tmpfilesdir" = "xyes"],
    [AC_MSG_ERROR([tmpfiles support requested but pkg-config unable to query systemd package])])
    with_tmpfilesdir=no],
   [with_tmpfilesdir="$def_tmpfilesdir"])])

AS_IF([test "x$with_tmpfilesdir" != "xno"],
      [AC_SUBST([tmpfilesdir], [$with_tmpfilesdir])])

AC_ARG_WITH([libcurl-zlib],
     [AS_HELP_STRING([--with-libcurl-zlib], [Enable if libcurl is GZIP capable])],,
     [with_libcurl_zlib=yes])

AS_IF([test "x$with_libcurl_zlib" != "xno"], [
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_WITH_LIBCURL_ZLIB=1"])
    AC_DEFINE([_ND_WITH_LIBCURL_ZLIB], [1], [Define if libcurl is GZIP capable.])
])

AC_ARG_WITH([persistentstatedir],
     [AS_HELP_STRING([--with-persistentstatedir=DIR], [Directory for persistent state files])],,
     [with_persistentstatedir=auto])

AS_IF([test "x$with_persistentstatedir" = "xyes" -o "x$with_persistentstatedir" = "xauto"],
    AC_SUBST([persistentstatedir], [$sysconfdir/netifyd]),
    AC_SUBST([persistentstatedir], [$with_persistentstatedir])
)

AC_ARG_WITH([volatilestatedir],
     [AS_HELP_STRING([--with-volatilestatedir=DIR], [Directory for volatile state files])],,
     [with_volatilestatedir=auto])

AS_IF([test "x$with_volatilestatedir" = "xyes" -o "x$with_volatilestatedir" = "xauto"],
    AC_SUBST([volatilestatedir], [$localstatedir/run/$PACKAGE_TARNAME]),
    AC_SUBST([volatilestatedir], [$with_volatilestatedir])
)

AC_ARG_WITH([plugin_libdir],
     [AS_HELP_STRING([--with-plugin-libdir=DIR], [Directory where plugin libraries are found])],,
     [with_plugin_libdir=auto])

AS_IF([test "x$with_plugin_libdir" = "xyes" -o "x$with_plugin_libdir" = "xauto"],
    AC_SUBST([plugin_libdir], [$libdir]),
    AC_SUBST([plugin_libdir], [$with_plugin_libdir])
)

AM_CONDITIONAL(USE_LIBGCRYPT_SYSTEM, false)

AC_ARG_WITH([local-libgcrypt],
    [AS_HELP_STRING([--with-local-libgcrypt],
      [Link nDPI against the local system libgcrypt instead of the bundled libgcrypt light])],,
    [with_local_libgcrypt=no])

AS_IF([test "x$with_local_libgcrypt" = "xyes"], [
    AM_CONDITIONAL(USE_LIBGCRYPT_SYSTEM, true)
    LIBS="${LIBS} -lgcrypt -lgpg-error"
])

# Parameters: --enable/disable

AC_ARG_ENABLE([libtcmalloc],
    [AS_HELP_STRING([--enable-libtcmalloc], [Enable Thread Caching malloc support [default=yes]])],
    [],
    [enable_libtcmalloc=yes])

AM_CONDITIONAL(USE_LIBTCMALLOC, false)
AM_CONDITIONAL(USE_LIBTCMALLOC_BUNDLED, false)

AS_IF([test "x$enable_libtcmalloc" = "xyes"], [

    AC_DEFINE([_ND_ENABLE_LIBTCMALLOC], [1],
        [Define to enable Thread Caching malloc support.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_LIBTCMALLOC=1"])

    PKG_CHECK_MODULES([LIBTCMALLOC], [libtcmalloc_minimal], [
        AM_CONDITIONAL(USE_LIBTCMALLOC, true)

        AC_LANG_PUSH([C++])
        AC_CHECK_HEADERS([gperftools/malloc_extension.h], [], [
          AC_MSG_ERROR([malloc_extensions.h not found])
        ])
        AC_LANG_POP([C++])
    ], [
        AM_CONDITIONAL(USE_LIBTCMALLOC, true)
        AM_CONDITIONAL(USE_LIBTCMALLOC_BUNDLED, true)

        LIBTCMALLOC_LIBS="${ac_abs_confdir}/libs/gperftools/.libs/libtcmalloc_minimal.a"
        LIBTCMALLOC_CFLAGS="-I ${ac_abs_confdir}/libs/gperftools/src"
    ])

    AM_COND_IF([USE_LIBTCMALLOC_BUNDLED], [
         AC_CONFIG_SUBDIRS([libs/gperftools])
         AC_MSG_NOTICE([using tcmalloc (gperftools) from bundled libs...])
     ])
])

AC_ARG_ENABLE([lean-and-mean],
    [AS_HELP_STRING([--enable-lean-and-mean], [Enable build for embedded systems [default=no]])],
    [],
    [enable_lean_and_mean=no])

AS_IF([test "x$enable_lean_and_mean" = "xyes"], [
    AC_DEFINE([_ND_LEAN_AND_MEAN], [1],
        [Define to build smallest possible binary.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_LEAN_AND_MEAN=1"])
    AM_CONDITIONAL(ENABLE_LEAN_AND_MEAN, true)
], [
    AM_CONDITIONAL(ENABLE_LEAN_AND_MEAN, false)
])

AC_ARG_ENABLE([extended-stats],
    [AS_HELP_STRING([--enable-extended-stats], [Enable the collection of additional flow statistics [default=yes]])],
    [],
    [enable_extended_stats=yes])

AS_IF([test "x$enable_extended_stats" = "xyes"], [
    AC_DEFINE([_ND_ENABLE_EXTENDED_STATS], [1],
        [Define to enable the collection of additional flow statistics.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_EXTENDED_STATS=1"])
    AM_CONDITIONAL(ENABLE_EXTENDED_STATS, true)
], [
    AM_CONDITIONAL(ENABLE_EXTENDED_STATS, false)
])

AC_ARG_ENABLE([ndpi-debug],
    [AS_HELP_STRING([--enable-ndpi-debug], [Enable nDPI debug messages [default=no]])],
    [],
    [enable_ndpi_debug=no])

AS_IF([test "x$enable_ndpi_debug" = "xyes"], [
    AC_DEFINE([_ND_ENABLE_NDPI_DEBUG], [1],
        [Define to enable nDPI debug messages.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_NDPI_DEBUG=1"])
])

AC_ARG_ENABLE([debug-stats],
    [AS_HELP_STRING([--enable-debug-stats], [Enable the collection of additional flow statistics [default=no]])],
    [],
    [enable_debug_stats=no])

AS_IF([test "x$enable_debug_stats" = "xyes"], [
    AC_DEFINE([_ND_ENABLE_DEBUG_STATS], [1],
        [Define to enable the output of debug statistics.])
    AS_VAR_APPEND([ND_DEFINES], [" -D_ND_ENABLE_DEBUG_STATS=1"])
    AM_CONDITIONAL(ENABLE_DEBUG_STATS, true)
], [
    AM_CONDITIONAL(ENABLE_DEBUG_STATS, false)
])

# Checks for required header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h net/ethernet.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/types.h sys/time.h sys/un.h syslog.h unistd.h], [], AC_MSG_ERROR([required header(s) not found.]))
AC_CHECK_HEADERS([netinet/in.h netinet/ip.h netinet/tcp.h netinet/udp.h], [], AC_MSG_ERROR([required netinet header(s) not found.]),
[[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])

# Check for optional header files.
AC_CHECK_HEADERS([endian.h pthread_np.h sys/cpuset.h sys/endian.h linux/ppp_defs.h net/ppp_defs.h stdalign.h])
AC_CHECK_HEADERS([pcap/sll.h pcap/vlan.h pcap/dlt.h])

# Check for optional parameters

# Checks for typedefs, structures, sizes, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_SIZEOF([long])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_STRNLEN

AC_CHECK_FUNCS([ftruncate memchr memset pathconf select socket strcasecmp strdup strerror])

AC_CHECK_FUNC([pthread_setname_np], [
    AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if pthread_setname_np is available.])
])
AC_CHECK_FUNC([pthread_attr_setaffinity_np], [
    AC_DEFINE([HAVE_PTHREAD_ATTR_SETAFFINITY_NP], [1], [Define if pthread_attr_setaffinity_np is available.])
])
AC_CHECK_FUNC([malloc_trim], [
    AC_DEFINE([HAVE_MALLOC_TRIM], [1], [Define if malloc_trim is available.])
])
AC_CHECK_FUNC([getprotobynumber_r], [
    AC_DEFINE([HAVE_GETPROTOBYNUMBER_R], [1], [Define if getprotobynumber_r is available.])
])

AX_GIT_VARS

AC_SUBST([GIT_SOURCE_URL], [https://gitlab.com/netify.ai/public/netify-agent.git])

# Defines substitution for pkg-config
AC_SUBST([ND_DEFINES], [$ND_DEFINES])

# Define hex version
AC_SUBST([ND_VERSION], [m4_esyscmd_s([tail -n 1 VERSION])]])

# Output files
AC_CONFIG_FILES([deploy/openwrt/Makefile deploy/openwrt/files/netifyd.init \
    deploy/openwrt/files/netifyd.config])
AC_CONFIG_FILES([libnetifyd.pc])
AC_CONFIG_FILES(
    [Makefile src/Makefile include/Makefile deploy/Makefile \
     doc/Makefile tests/Makefile util/Makefile])
AC_CONFIG_FILES([deploy/buildroot/package/netifyd/netifyd.mk])
AC_CONFIG_FILES([deploy/debian/Makefile])
AC_CONFIG_FILES([deploy/freebsd/Makefile])
AC_CONFIG_FILES([deploy/rpm/Makefile])
AC_CONFIG_FILES([deploy/systemd/Makefile])
AC_CONFIG_FILES([doc/netifyd.8 doc/netifyd.conf.5])
AC_CONFIG_FILES([util/generate-protocol-csv.sh],
    [chmod +x util/generate-protocol-csv.sh])
AC_CONFIG_FILES([util/generate-alpn-include.sh],
    [chmod +x util/generate-alpn-include.sh])

AC_OUTPUT

AS_BOX([${PACKAGE_NAME} v${PACKAGE_VERSION}])
case "${host_os}" in
    linux*)
        AC_MSG_NOTICE([Conntrack support: ${enable_conntrack}])
        AC_MSG_NOTICE([Conntrack meta-data: ${enable_conntrack_mdata}])
        AC_MSG_NOTICE([Netlink support: ${enable_netlink}])
        AC_MSG_NOTICE([TPv3 capture support: ${enable_tpacketv3}])
        AC_MSG_NOTICE([NFQUEUE capture support: ${enable_nfqueue}])
    ;;
esac

AC_MSG_NOTICE([Use libCURL zlib support: ${with_libcurl_zlib}])
AC_MSG_NOTICE([Use system libgcrypt: ${with_local_libgcrypt}])
AC_MSG_NOTICE([Use thread-caching malloc: ${enable_libtcmalloc}])
AC_MSG_NOTICE([Enable lean-and-mean build: ${enable_lean_and_mean}])
AC_MSG_NOTICE([Enable extended flow stats: ${enable_extended_stats}])
AC_MSG_NOTICE([Enable debug stats: ${enable_debug_stats}])
AC_MSG_NOTICE([Installation prefix directory: ${prefix}])
AC_MSG_NOTICE([Persistent state directory: ${persistentstatedir}])
AC_MSG_NOTICE([Volatile state directory: ${volatilestatedir}])
AC_MSG_NOTICE([Shared data directory: ${datadir}/${PACKAGE_TARNAME}])
AC_MSG_NOTICE([Default configuration filename: ${sysconfdir}/${PACKAGE_TARNAME}.conf])
AC_MSG_NOTICE([Default PID filename: ${volatilestatedir}/${PACKAGE_TARNAME}.pid])
