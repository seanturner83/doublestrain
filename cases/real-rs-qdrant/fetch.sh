#!/bin/sh
# Fetch the pinned Qdrant v1.12.5 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=27260abda78509e1a3e8822c8d8819c4fe189f5b
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/qdrant/qdrant.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-qdrant at $(git -C repo rev-parse --short HEAD)"
