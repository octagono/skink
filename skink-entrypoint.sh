#!/bin/sh
set -e

if [ -n "$SKINK_PASS" ]; then
    set -- --pass "$SKINK_PASS" "$@"
fi

exec /Skink "$@"
