#!/bin/sh
# Fetch the pinned OWASP NodeGoat checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=c5cb68a7084e4ae7dcc60e6a98768720a81841e8
[ -d repo/.git ] || git clone -q https://github.com/OWASP/NodeGoat.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "NodeGoat at $(git -C repo rev-parse --short HEAD)"
