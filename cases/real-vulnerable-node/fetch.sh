#!/bin/sh
# Fetch the pinned cr0hn/vulnerable-node checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=d68f2a3c9277ece2c2feb9976052033bdecd7fbe
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/cr0hn/vulnerable-node.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "vulnerable-node at $(git -C repo rev-parse --short HEAD)"
