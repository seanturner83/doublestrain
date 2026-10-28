#!/bin/sh
# Fetch the pinned Meilisearch v1.13.3 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=4afb3811d7cf7a8ffbf974f708bbf0034a27474f
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/meilisearch/meilisearch.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-meilisearch at $(git -C repo rev-parse --short HEAD)"
