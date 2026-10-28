#!/bin/sh
# Fetch the pinned paperless-ngx v2.7.2 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=9885ca5103af8682780c22b421192421171d78b0
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/paperless-ngx/paperless-ngx.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-paperless at $(git -C repo rev-parse --short HEAD)"
