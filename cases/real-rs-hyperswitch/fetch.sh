#!/bin/sh
# Fetch the pinned Hyperswitch v1.112.0 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=4e250b71c06bde9de71fbcf319bb5f6dea6a7cbb
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/juspay/hyperswitch.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-hyperswitch at $(git -C repo rev-parse --short HEAD)"
