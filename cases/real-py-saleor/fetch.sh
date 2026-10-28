#!/bin/sh
# Fetch the pinned saleor 3.20.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=1ce97784dcdc073be328ae9bc1179ccb915e831d
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/saleor/saleor.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-saleor at $(git -C repo rev-parse --short HEAD)"
