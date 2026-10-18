#!/bin/sh
# Fetch the pinned gothinkster/golang-gin-realworld-example-app checkout this case was labelled against.
# Read-only use: nothing is built, installed or executed (govulncheck type-checks it, sandboxed).
set -eu
cd "$(dirname "$0")"
COMMIT=626c372d259472148d93303f74aa9b9a1cdcef24
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/gothinkster/golang-gin-realworld-example-app.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-go-realworld at $(git -C repo rev-parse --short HEAD)"
