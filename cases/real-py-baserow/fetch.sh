#!/bin/sh
# Fetch the pinned Baserow 1.29.3 (backend/) checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=d5b05c5ede0d0abd123f7469d04cfbf7b1b437e4
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/bram2w/baserow.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-baserow at $(git -C repo rev-parse --short HEAD)"
