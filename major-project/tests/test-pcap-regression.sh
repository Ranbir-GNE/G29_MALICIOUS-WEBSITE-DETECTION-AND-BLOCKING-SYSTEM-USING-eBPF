#!/bin/bash

set -euo pipefail

if [ -z "${TESTDIR:-}" ]; then
    TESTDIR=$(dirname $0)
    export TESTDIR
fi

VALGRIND=/usr/loca/bin/valgrind

ND_PCAPS=$(find "${TESTDIR}/pcap/" -name '*.cap.gz' | sort)
NDPI_PCAPS=$(sort "${TESTDIR}/ndpi-pcap-files.txt" | egrep -v '^#' |\
    xargs -I{} find "${TESTDIR}/../libs/ndpi/tests/cfgs/default/pcap" -name '{}*cap*' |\
    egrep -v -- '-test.cap$')

PCAPS="$(echo ${ND_PCAPS} ${NDPI_PCAPS} | sort)"

CONF="${TESTDIR}/netifyd-test-pcap.conf"
NETIFYD="${TESTDIR}/../src/.libs/netifyd"
NETWORK=192.168.242.0/24
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

export LD_LIBRARY_PATH="${TESTDIR}/../src/.libs/"

echo -e "\nStarting capture tests..."

run_test() {
    BASE=$(echo $1 | sed -e 's/\.[pc]*ap.*$//')
    NAME=$(basename "${BASE}")
    LOG=$(printf "%s/test-pcap-logs/%s.log" ${TESTDIR} ${NAME})
    if echo $1 | egrep -q '\.gz$'; then
        zcat $1 > ${BASE}-test.cap || exit $?
    else
        cat $1 > ${BASE}-test.cap || exit $?
    fi
    echo -e "\n${BOLD}>>> ${NAME}${NORMAL}"
    CMD="${NETIFYD} -vvv -t -c $CONF --thread-detection-cores=1 --verbose-flag no-event-dpi-new --verbose-flag event-dpi-complete -I ${BASE}-test.cap -A $NETWORK -T ${LOG}"
    if [ "x${WITH_VALGRIND}" == "xyes" ]; then
        CMD="/usr/local/bin/valgrind --tool=memcheck --leak-check=full --track-origins=yes --log-file=/tmp/${NAME}.log ${CMD}"
    else
        ulimit -c unlimited || true
    fi
    echo $CMD
    $CMD || exit $?
    rm -f ${BASE}-test.cap
}

if [ $# -eq 0 ]; then
    for PCAP in $PCAPS; do
        run_test $PCAP
    done
else
    while [ $# -gt 0 ]; do
        run_test $1
        shift 1
    done
fi

echo "Capture test complete."

exit 0
