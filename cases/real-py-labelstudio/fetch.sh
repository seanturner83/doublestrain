#!/bin/sh
# Fetch the pinned Label Studio 1.13.1 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=d9b816a3781ee806bba50c8c5589fcdb8555a277
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/HumanSignal/label-studio.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-labelstudio at $(git -C repo rev-parse --short HEAD)"
