#serial 1

AC_DEFUN([AX_FUNC_WHICH_NFT_CMD_FROM_BUFFER], [

    AC_LANG_PUSH([C])
    AC_MSG_CHECKING([how many arguments nft_run_cmd_from_buffer() takes])

    AC_CACHE_VAL([ac_cv_func_which_nft_run_cmd_from_buffer], [

################################################################

ac_cv_func_which_nft_run_cmd_from_buffer=unknown

#
# ONE ARGUMENT (sanity check)
#

# This should fail, as there is no variant of nft_run_cmd_from_buffer() that takes
# a single argument. If it actually compiles, then we can assume that
# netdb.h is not declaring the function, and the compiler is thereby
# assuming an implicit prototype. In which case, we're out of luck.
#
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <nftables/libnftables.h>],
        [
            struct nft_ctx *ctx = NULL;
            (void)nft_run_cmd_from_buffer(ctx) /* ; */
        ])],
    [ac_cv_func_which_nft_run_cmd_from_buffer=no])

#
# THREE ARGUMENTS
#

if test "$ac_cv_func_which_nft_run_cmd_from_buffer" = "unknown"; then

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <nftables/libnftables.h>],
        [
            struct nft_ctx *ctx = NULL;
            char buf@<:@1024@:>@;
            size_t buflen = 1024;
            (void)nft_run_cmd_from_buffer(ctx, buf, buflen) /* ; */
        ])],
    [ac_cv_func_which_nft_run_cmd_from_buffer=three])

fi

#
# TWO ARGUMENTS
#

if test "$ac_cv_func_which_nft_run_cmd_from_buffer" = "unknown"; then

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <nftables/libnftables.h>],
        [
            struct nft_ctx *ctx = NULL;
            const char *buf = "add table inet autoconf";
            (void)nft_run_cmd_from_buffer(ctx, buf) /* ; */
        ])],
    [ac_cv_func_which_nft_run_cmd_from_buffer=two])

fi

################################################################

]) dnl end AC_CACHE_VAL

case "$ac_cv_func_which_nft_run_cmd_from_buffer" in
    two|three)
    AC_DEFINE([HAVE_NFT_CMD_FROM_BUFFER], [1],
              [Define to 1 if you have some form of nft_run_cmd_from_buffer().])
    ;;
esac

case "$ac_cv_func_which_nft_run_cmd_from_buffer" in
    two)
    AC_MSG_RESULT([two])
    AC_DEFINE([HAVE_FUNC_NFT_CMD_FROM_BUFFER_2], [1],
              [Define to 1 if you have the two-argument form of nft_run_cmd_from_buffer().])
    ;;

    three)
    AC_MSG_RESULT([three])
    AC_DEFINE([HAVE_FUNC_NFT_CMD_FROM_BUFFER_3], [1],
              [Define to 1 if you have the three-argument form of nft_run_cmd_from_buffer().])
    ;;

    no)
    AC_MSG_RESULT([cannot find function declaration in libnftables.h])
    ;;

    unknown)
    AC_MSG_RESULT([can't tell])
    ;;

    *)
    AC_MSG_ERROR([internal error])
    ;;
esac

AC_LANG_POP

]) dnl end AC_DEFUN
