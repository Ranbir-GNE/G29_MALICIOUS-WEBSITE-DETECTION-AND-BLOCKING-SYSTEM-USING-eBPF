#!/usr/bin/env bash
#!/bin/bash -x

set -euo pipefail

: ${OPTION_GDB:=disable}
: ${OPTION_VALGRIND:=disable}
: ${NETIFYD_PREFIX:=/tmp/netify-agent}
: ${NETIFYD_OPTIONS:=-d --run-without-sources --thread-detection-cores=4}
: ${NETIFYD_CONF:=$(pwd)/netifyd-debug.conf}

if [ -z "${NETIFYD_CONF}" -a -f netifyd-debug.conf ]; then
  NETIFYD_CONF="$(pwd)/netifyd-debug.conf"
fi

echo "Options:"
echo " OPTION_GDB: ${OPTION_GDB}"
echo " OPTION_VALGRIND: ${OPTION_VALGRIND}"
echo " NETIFYD_PREFIX: ${NETIFYD_PREFIX}"
echo " NETIFYD_OPTIONS: ${NETIFYD_OPTIONS}"

if [ ! -d "${NETIFYD_PREFIX}" ]; then
  echo "ERROR: The Netify Agent prefix path does not exist."
  exit 1
fi

echo " NETIFYD_CONF: ${NETIFYD_CONF}"

if [ ! -f "${NETIFYD_CONF}" ]; then
  echo "ERROR: The Netify Agent configuration file was not found."
  exit 1
fi

NETIFYD_SO=$(find ${NETIFYD_PREFIX} -name 'libnetifyd.so')

if [ -z "${NETIFYD_SO}" -o ! -x "${NETIFYD_PREFIX}/usr/sbin/netifyd" ]; then
  echo "ERROR: The Netify Agent is not installed under: ${NETIFYD_PREFIX}"
  exit 1
fi

export LD_LIBRARY_PATH=$(dirname ${NETIFYD_SO})
echo " LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"

ARGS="-c ${NETIFYD_CONF} ${NETIFYD_OPTIONS} $@"
echo -e "Arguments:\n $ARGS"

export NETIFYD_DESTDIR="${NETIFYD_PREFIX}"

SUDO=$(which sudo)

if [ -z "${SUDO}" ]; then
  echo "WARNING: sudo not found, running as: ${USER}"
  exec ${NETIFYD_PREFIX}/usr/sbin/netifyd $ARGS
else
  if [ "${OPTION_GDB}" == "enable" ]; then
    grep -E '^#define' config.h | sed -e 's/#define/macro define/g' > defines.gdb
    exec ${SUDO} LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
      gdb -x defines.gdb -ex 'break main' --args ${NETIFYD_PREFIX}/usr/sbin/netifyd $ARGS
  elif [ "${OPTION_VALGRIND}" != "disable" ]; then
    exec ${SUDO} LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
      valgrind --tool=${OPTION_VALGRIND} --vgdb=yes --track-origins=yes \
        --log-file=/tmp/netifyd-$(date '+%s').log ${NETIFYD_PREFIX}/usr/sbin/netifyd $ARGS
  else
    exec ${SUDO} LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
      ${NETIFYD_PREFIX}/usr/sbin/netifyd $ARGS
  fi
fi

exit 0
