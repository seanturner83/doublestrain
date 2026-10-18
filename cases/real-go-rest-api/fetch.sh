#!/bin/sh
# Fetch the pinned qiangxue/go-rest-api checkout this case was labelled against.
# Read-only use: nothing is built, installed or executed (govulncheck type-checks it, sandboxed).
set -eu
cd "$(dirname "$0")"
COMMIT=c3101332148b4aa45f637605e394cb0d033dae97
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/qiangxue/go-rest-api.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-go-rest-api at $(git -C repo rev-parse --short HEAD)"
