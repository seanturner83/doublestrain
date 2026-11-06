#!/bin/sh
# Fetch the pinned koel v7.4.1 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=374211e7c8ea7c8a28d0602f6ca1e93ddd0a0c0b
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/koel/koel.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-koel at $(git -C repo rev-parse --short HEAD)"
