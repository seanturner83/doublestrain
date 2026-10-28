#!/bin/sh
# Fetch the pinned InvenTree 0.16.9 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=e0756a70069a72ba00cfe42444d936665c8b69f7
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/inventree/InvenTree.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-inventree at $(git -C repo rev-parse --short HEAD)"
