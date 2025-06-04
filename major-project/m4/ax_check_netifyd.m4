dnl AX_CHECK_NETIFYD
dnl ----------------
dnl
dnl Checks for Netify Agent

AC_DEFUN([AX_CHECK_NETIFYD], [
	PKG_CHECK_MODULES([LIBNETIFYD], [libnetifyd >= $NETIFY_MINVER],
	    [ac_persistentstatedir=`$PKG_CONFIG --variable=persistentstatedir libnetifyd`;\
	     ac_volatilestatedir=`$PKG_CONFIG --variable=volatilestatedir libnetifyd`],
	    [AC_MSG_ERROR([Netify Agent pkg-config not found])]
	)

	AS_IF([test "x$ac_persistentstatedir" = "x"],
	    AC_MSG_ERROR([couldn't determine Netify Agent's persistent state directory]),
	    AC_SUBST(persistentstatedir, $ac_persistentstatedir)
	)

	AS_IF([test "x$ac_volatilestatedir" = "x"],
	    AC_MSG_ERROR([couldn't determine Netify Agent's volatile state directory]),
	    AC_SUBST(volatilestatedir, $ac_volatilestatedir)
	)
])
