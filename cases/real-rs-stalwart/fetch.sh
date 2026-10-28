#!/bin/sh
# Fetch the pinned Stalwart mail-server v0.11.8 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=7dc620816f355a09830691af495b2a63c05fe971
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/stalwartlabs/mail-server.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-stalwart at $(git -C repo rev-parse --short HEAD)"
