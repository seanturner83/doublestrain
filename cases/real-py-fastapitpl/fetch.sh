#!/bin/sh
# Fetch the pinned full-stack-fastapi-template 0.8.0 (backend/) checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=2eb8f5b624e60d4074318dec6f33400080eceef9
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/fastapi/full-stack-fastapi-template.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-fastapitpl at $(git -C repo rev-parse --short HEAD)"
