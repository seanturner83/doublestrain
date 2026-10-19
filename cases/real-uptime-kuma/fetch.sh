#!/bin/sh
# Fetch the pinned uptime-kuma 1.21.0 checkout this case was labelled against (held out from the
# Jelly guard's design). Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=72317633d982a111f74c23c6b675bdba93e8f6aa
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/louislam/uptime-kuma.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-uptime-kuma at $(git -C repo rev-parse --short HEAD)"
