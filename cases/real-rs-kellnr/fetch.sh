#!/bin/sh
# Fetch the pinned Kellnr v5.2.7 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=622770c76272fc59fd9041c2b7f257134d3daa8d
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/kellnr/kellnr.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-kellnr at $(git -C repo rev-parse --short HEAD)"
