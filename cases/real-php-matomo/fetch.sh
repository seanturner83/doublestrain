#!/bin/sh
# Fetch the pinned matomo 5.4.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=bd1721a8afe4762c7b9a46116467c995b724a3dd
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/matomo-org/matomo.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-matomo at $(git -C repo rev-parse --short HEAD)"
