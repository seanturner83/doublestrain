#!/bin/sh
# Fetch the pinned snipe-it v8.1.4 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=58d6443331a1942b9ab3c6633b251b2d8abc74ff
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/grokability/snipe-it.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-snipeit at $(git -C repo rev-parse --short HEAD)"
