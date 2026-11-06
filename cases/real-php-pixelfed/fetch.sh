#!/bin/sh
# Fetch the pinned pixelfed v0.12.3 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=4c245cf429330d01fcb8ebeb9aa8c84a9574a645
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/pixelfed/pixelfed.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-pixelfed at $(git -C repo rev-parse --short HEAD)"
