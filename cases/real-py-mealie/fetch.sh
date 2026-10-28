#!/bin/sh
# Fetch the pinned mealie v1.4.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=f709d11952ca8552214e4b9e8c2a189bc11bfb2a
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/mealie-recipes/mealie.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-mealie at $(git -C repo rev-parse --short HEAD)"
