#!/bin/bash

set -eo pipefail

NDPI=$(realpath "$(dirname "$0")/../libs/ndpi")

if [ ! -d "$NDPI" ]; then
  echo "NDPI source directory not found."
  exit 1
fi

while read LINE; do
  if [[ "$LINE" =~ ^ID ]]; then
    # ID# 72 (HART-IP)
    ID=$(echo "$LINE" | sed -Ee 's/^ID# ([0-9]+).*$/\1/')
    DEFINE=$(echo "$LINE" |\
      grep -E "^[[:space:]]*NDPI_.*[[:space:]]*=[[:space:]]*$ID," \
        $NDPI/src/include/ndpi_protocol_ids.h |\
      sed -E \
        -e "s/^[[:space:]]*(NDPI_.*)[[:space:]]*=[[:space:]]*$ID,.*$/\1/" \
        -e 's/[[:space:]]*//g')

    if [ -z "$DEFINE" ]; then
      echo "$LINE: Not found."
      continue
    fi

    if grep -qE "$DEFINE" $NDPI/src/lib/protocols/*.c; then
      echo "$DEFINE: $ID"
    else
      echo "$DEFINE: $ID: No dissector"
    fi
  fi
done
