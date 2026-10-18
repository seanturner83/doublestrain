#!/bin/sh
# Fetch the pinned sahat/hackathon-starter checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=d7a20cce5e41f45f14eaf400af874f86817aea0d
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/sahat/hackathon-starter.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "hackathon-starter at $(git -C repo rev-parse --short HEAD)"
