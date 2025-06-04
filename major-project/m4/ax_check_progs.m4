dnl AX_CHECK_PROGS
dnl --------------
dnl
dnl Checks for various build tools

AC_DEFUN([AX_CHECK_PROGS], [
  AC_PATH_PROG([BASH], [bash], [false])
  AS_IF([test "x$ac_cv_path_BASH" != "xfalse"], [
      AC_SUBST([ND_PATH_BASH], [$ac_cv_path_BASH])
  ], [
      AC_MSG_WARN([bash not found.])
      AC_SUBST([ND_PATH_BASH], [sh])
  ])

  case "${host_os}" in
      linux*)
      AC_PATH_PROG([TAR], [tar], [false])
      AS_IF([test "x$ac_cv_path_TAR" = "xfalse"], [
          AC_MSG_ERROR([tar not found.])
      ])
      ;;
      freebsd*)
      AC_PATH_PROG([GMAKE], [gmake], [false])
      AS_IF([test "x$ac_cv_path_GMAKE" = "xfalse"], [
          AC_MSG_ERROR([gmake not found.])
      ])
      AC_PATH_PROG([TAR], [gtar], [false])
      AS_IF([test "x$ac_cv_path_TAR" = "xfalse"], [
        AC_MSG_WARN([gtar not found.])
        AC_PATH_PROG([TAR], [tar], [false])
      ])
      ;;
  esac
])
