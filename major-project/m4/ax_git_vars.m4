dnl AX_GIT_VARS
dnl -----------
dnl
dnl Sets various useful Git variables

AC_DEFUN([AX_GIT_VARS], [
  if test -e ".git"; then :
      GIT_TAG=`git log -1 --format=%h`
      GIT_DATE=`git log -1 --format=%cd`
      GIT_DATE_UNIX=`git log -1 --format=%ct`

      GIT_LAST_COMMIT_HASH=`git log -1 --format=%H`
      case "${host_os}" in
          linux*)
              GIT_LAST_COMMIT_DATE=`date -d "@${GIT_DATE_UNIX}" '+%F'`
          ;;
      *)
              GIT_LAST_COMMIT_DATE=`date -r "${GIT_DATE_UNIX}" '+%F'`
          ;;
      esac

      AC_SUBST([GIT_LAST_COMMIT_HASH], [$GIT_LAST_COMMIT_HASH])
      AC_SUBST([GIT_LAST_COMMIT_DATE], [$GIT_LAST_COMMIT_DATE])

      # On CentOS 6 `git rev-list HEAD --count` does not work
      GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
      GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
      GIT_RELEASE="${PACKAGE_VERSION}-${GIT_BRANCH}-${GIT_NUM}-${GIT_TAG}"
    else
        GIT_RELEASE="${PACKAGE_VERSION}"
        GIT_DATE=`date`
    fi

    AC_DEFINE_UNQUOTED(GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
    AC_DEFINE_UNQUOTED(GIT_DATE, "${GIT_DATE}", [Last GIT change])
])
