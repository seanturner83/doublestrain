#!/bin/sh
# Fetch the pinned eddycjy/go-gin-example checkout this case was labelled against.
# Read-only use: nothing is built, installed or executed (govulncheck type-checks it, sandboxed).
set -eu
cd "$(dirname "$0")"
COMMIT=4f5174ca325b37f23edadad7c88d49586816a69c
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/eddycjy/go-gin-example.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-go-gin-example at $(git -C repo rev-parse --short HEAD)"
