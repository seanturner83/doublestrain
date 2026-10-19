#!/bin/sh
# Fetch the pinned parse-server 4.10.4 checkout this case was labelled against (held out from the
# Jelly guard's design). Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=4ac4b7f71002ed4fbedbb901db1f6ed1e9ac5559
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/parse-community/parse-server.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-parse-server at $(git -C repo rev-parse --short HEAD)"
