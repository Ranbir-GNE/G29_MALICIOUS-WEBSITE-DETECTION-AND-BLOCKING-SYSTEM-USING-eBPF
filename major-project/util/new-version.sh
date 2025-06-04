#!/bin/bash

set -eo pipefail

VER=$(head -n 1 VERSION)

read -e -i "$VER" -p "New version: " VER_NEW

if [ "$VER_NEW" == "$VER" ]; then
  echo "Version unchanged; aborting..."
  exit 1
fi

if [[ ! "$VER_NEW" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "Version invalid; aborting..."
  exit 1
fi

VER_HEX=$(printf "0x%02x%02x%02x00" \
  "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")

printf "%s\n%s" "$VER_NEW" "${VER_HEX}" > VERSION

exit 0
