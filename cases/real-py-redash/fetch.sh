#!/bin/sh
# Fetch the pinned Redash v25.1.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=d1c255b7d80bfd9631962ad84a47a69a2bd73b16
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/getredash/redash.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-redash at $(git -C repo rev-parse --short HEAD)"
