#!/bin/sh
# Fetch the pinned AppFlowy-Cloud 0.9.36 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=87a12b37f51d5f30253dc7bd8431bbc9832fb9ec
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/AppFlowy-IO/AppFlowy-Cloud.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-appflowy at $(git -C repo rev-parse --short HEAD)"
