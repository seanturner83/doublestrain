#!/bin/sh
# Fetch the pinned Plane v0.25.3 (apiserver/) checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=72307ec100706a91dde6d9b277f974e29414fd83
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/makeplane/plane.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-plane at $(git -C repo rev-parse --short HEAD)"
