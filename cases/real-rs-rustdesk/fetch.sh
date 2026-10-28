#!/bin/sh
# Fetch the pinned rustdesk-server 1.1.14 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=8557c4ab8259a9084879ad78a41c5a9539fd75a3
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/rustdesk/rustdesk-server.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-rustdesk at $(git -C repo rev-parse --short HEAD)"
