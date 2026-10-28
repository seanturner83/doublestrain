#!/bin/sh
# Fetch the pinned SearXNG master @ 2024-06-30 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=39aaac40d63d53555b7fc12d56f0825c85ecf567
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/searxng/searxng.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-searxng at $(git -C repo rev-parse --short HEAD)"
