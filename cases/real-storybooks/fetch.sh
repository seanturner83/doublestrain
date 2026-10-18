#!/bin/sh
# Fetch the pinned bradtraversy/storybooks checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=865ff4eaefa62be01d4dd57fa2f2c617b73798c8
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/bradtraversy/storybooks.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-storybooks at $(git -C repo rev-parse --short HEAD)"
