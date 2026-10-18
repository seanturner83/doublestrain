#!/bin/sh
# Fetch the pinned snyk-labs/nodejs-goof checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=add14ba59e98240d9e00a235dd7d42cd61ae9912
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/snyk-labs/nodejs-goof.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "nodejs-goof at $(git -C repo rev-parse --short HEAD)"
