#!/bin/sh
# Fetch the pinned part-db v1.17.2 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=8b417d6441cf4f5e8bf414af7d243a049c81c727
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/Part-DB/Part-DB-server.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-partdb at $(git -C repo rev-parse --short HEAD)"
