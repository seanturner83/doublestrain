#!/bin/sh
# Fetch the pinned linkace v2.1.9 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=2b141a1825f05232cb7e514f7b8f291b0c391abc
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/Kovah/LinkAce.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-linkace at $(git -C repo rev-parse --short HEAD)"
