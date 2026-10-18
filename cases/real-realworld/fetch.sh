#!/bin/sh
# Fetch the pinned gothinkster/node-express-realworld-example-app checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=30b68e1e881462b2f4164ea09ab4c4f5699c7b0b
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/gothinkster/node-express-realworld-example-app.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "realworld at $(git -C repo rev-parse --short HEAD)"
