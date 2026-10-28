#!/bin/sh
# Fetch the pinned Svix server v1.63.1 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=01a785853652f3d8d58a96b9222888ede2e572f0
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/svix/svix-webhooks.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-svix at $(git -C repo rev-parse --short HEAD)"
