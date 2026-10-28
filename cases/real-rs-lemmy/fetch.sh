#!/bin/sh
# Fetch the pinned Lemmy 0.19.7 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=fc8280a9b73d87780e1cb5f9d7f2de2d7e96a5e9
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/LemmyNet/lemmy.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-lemmy at $(git -C repo rev-parse --short HEAD)"
