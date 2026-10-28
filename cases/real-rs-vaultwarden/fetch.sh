#!/bin/sh
# Fetch the pinned Vaultwarden 1.32.4 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=38aad4f7bedfb4279ecb385e036b1d84f3d59483
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/dani-garcia/vaultwarden.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-rs-vaultwarden at $(git -C repo rev-parse --short HEAD)"
