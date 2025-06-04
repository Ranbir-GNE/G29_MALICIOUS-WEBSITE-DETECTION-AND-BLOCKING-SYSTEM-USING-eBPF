#!/bin/bash

set -eo pipefail

if [ $# -ge 1 ]; then
  grep '^nsd:' "$1" | while read LINE; do
    APP_ID=$(echo $LINE | cut -d: -f 2)
    PROTO_ID=$(echo $LINE | cut -d: -f 3)
    FXPR=$(echo $LINE | cut -d: -f 4 | base64 -d)

    printf "App ID: %d, Proto ID: %d\nFlow Expr: %s\n\n" "$APP_ID" "$PROTO_ID" "$FXPR"
  done
fi
