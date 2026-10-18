#!/bin/sh
# Fetch the pinned payatu/vuln-nodejs-app checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=bc3c90920ba4e1c668d954e5027d9ca814d2d5c6
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/payatu/vuln-nodejs-app.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-vuln-nodejs-app at $(git -C repo rev-parse --short HEAD)"
