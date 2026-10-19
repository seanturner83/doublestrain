#!/bin/sh
# Fetch the pinned private-gpt v0.6.2 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=22904ca8ad1b812f7e2e448432b3bca5941808ac
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/zylon-ai/private-gpt.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-private-gpt at $(git -C repo rev-parse --short HEAD)"
