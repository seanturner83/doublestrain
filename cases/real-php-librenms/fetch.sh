#!/bin/sh
# Fetch the pinned librenms 25.5.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=88fe1a7abdb500d9a2d4c45f9872df54c9ff8062
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/librenms/librenms.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-librenms at $(git -C repo rev-parse --short HEAD)"
