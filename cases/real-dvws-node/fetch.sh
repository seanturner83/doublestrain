#!/bin/sh
# Fetch the pinned snoopysecurity dvws-node checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=eb6e2886f2206b88bf709fe1fa311adc3ae3c34f
[ -d repo/.git ] || git clone -q https://github.com/snoopysecurity/dvws-node.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "dvws-node at $(git -C repo rev-parse --short HEAD)"
