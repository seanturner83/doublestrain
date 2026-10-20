#!/bin/sh
# Fetch the pinned DocsGPT 0.13.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=fa01f86b19eda2364525585cd7d3e7bab76373ee
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/arc53/DocsGPT.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-docsgpt at $(git -C repo rev-parse --short HEAD)"
