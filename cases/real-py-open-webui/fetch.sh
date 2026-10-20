#!/bin/sh
# Fetch the pinned open-webui v0.4.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=3c334320921caaeac8ec587dc2e227e3a886177c
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/open-webui/open-webui.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-open-webui at $(git -C repo rev-parse --short HEAD)"
