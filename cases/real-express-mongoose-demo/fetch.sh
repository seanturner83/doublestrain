#!/bin/sh
# Fetch the pinned madhums/node-express-mongoose-demo checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=8a134ab5deeef553d6de51d91d4ed8ee378acace
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/madhums/node-express-mongoose-demo.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-express-mongoose-demo at $(git -C repo rev-parse --short HEAD)"
