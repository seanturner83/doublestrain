#!/bin/sh
# Fetch the pinned Atuin v18.4.0 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=dc7c26a640b1a134528caa894b3339c443b917b4
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/atuinsh/atuin.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-rs-atuin at $(git -C repo rev-parse --short HEAD)"
