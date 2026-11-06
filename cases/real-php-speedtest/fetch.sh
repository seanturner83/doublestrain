#!/bin/sh
# Fetch the pinned speedtest-tracker v1.6.2 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=7a61fd77623653b0f0a2374c9e1d041ab3487d78
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/alexjustesen/speedtest-tracker.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-speedtest at $(git -C repo rev-parse --short HEAD)"
