#!/bin/sh
# Fetch the pinned Dify 0.15.8 (api/) checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=4b938ab18d39b58a1ecad00c501cca1d78768e3f
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/langgenius/dify.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-dify at $(git -C repo rev-parse --short HEAD)"
