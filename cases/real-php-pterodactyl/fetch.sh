#!/bin/sh
# Fetch the pinned pterodactyl v1.11.11 checkout this case was labelled against.
# Read-only use: nothing is installed or executed (no composer install).
set -eu
cd "$(dirname "$0")"
COMMIT=ac16af6d0a704c009240f18cfe3b31ca1dc24923
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/pterodactyl/panel.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-php-pterodactyl at $(git -C repo rev-parse --short HEAD)"
