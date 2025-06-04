dnl AX_BUILD_UUID
dnl --------------
dnl
dnl Generate a random build UUID

AC_DEFUN([AX_BUILD_UUID], [
	BUILD_UUID=00000000-0000-0000-0000-000000000000

	AC_PATH_PROG([uuidgen], [uuidgen], [false])
	AS_IF([test "x$ac_cv_path_uuidgen" != "xfalse"], [
	  BUILD_UUID=`${ac_cv_path_uuidgen}`
	], [
	  AC_PATH_PROG([uuid], [uuid], [false])
	  AS_IF([test "x$ac_cv_path_uuid" != "xfalse"], [
	    BUILD_UUID=`${ac_cv_path_uuid}`
	  ])
	])
])
