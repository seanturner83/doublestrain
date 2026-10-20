#!/bin/sh
# Fetch the pinned ragflow v0.15.0 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=a5cf6fc5460d73ed8bbef28ad61b65139288e63d
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/infiniflow/ragflow.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-ragflow at $(git -C repo rev-parse --short HEAD)"
