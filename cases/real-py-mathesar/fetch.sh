#!/bin/sh
# Fetch the pinned Mathesar 0.2.5 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=05dee0acc8106c068a0732c810f4f03e6121055d
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/mathesar-foundation/mathesar.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-mathesar at $(git -C repo rev-parse --short HEAD)"
