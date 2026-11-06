#!/bin/sh
# Fetch the pinned kimai 2.34.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=6e26a37c4d1fd33c7cc26fb4ae90ca4f0a516595
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/kimai/kimai.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-kimai at $(git -C repo rev-parse --short HEAD)"
