#!/bin/sh
# Fetch the pinned khoj 2.0.0-beta.20 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=c41e37d73423768af311831759fdc235d8e15407
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/khoj-ai/khoj.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-khoj at $(git -C repo rev-parse --short HEAD)"
