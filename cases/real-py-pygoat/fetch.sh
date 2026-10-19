#!/bin/sh
# Fetch the pinned pygoat checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=19d17cc8874861142b330636d068bbde54e86b85
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/adeyosemanputra/pygoat.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-pygoat at $(git -C repo rev-parse --short HEAD)"
