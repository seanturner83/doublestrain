#!/bin/sh
# Fetch the pinned jsbin checkout this case was labelled against (held out from the
# Jelly guard's design). Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=c7e93886d08b4862aa5850128c055acfe81d3589
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/jsbin/jsbin.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-jsbin at $(git -C repo rev-parse --short HEAD)"
