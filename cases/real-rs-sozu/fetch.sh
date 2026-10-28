#!/bin/sh
# Fetch the pinned Sozu 1.0.3 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=1a611cb9daef06dbf825d56f2951a4d4660faa8f
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/sozu-proxy/sozu.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-sozu at $(git -C repo rev-parse --short HEAD)"
