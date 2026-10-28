#!/bin/sh
# Fetch the pinned Quickwit v0.8.2 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=42766b8b70ac848950ac3aa69f3762114b4aed3d
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/quickwit-oss/quickwit.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-quickwit at $(git -C repo rev-parse --short HEAD)"
