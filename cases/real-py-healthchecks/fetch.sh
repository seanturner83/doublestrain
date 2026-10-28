#!/bin/sh
# Fetch the pinned healthchecks v3.4 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=17d01ee6e25d73932c22500518cdad6169baa730
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/healthchecks/healthchecks.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-healthchecks at $(git -C repo rev-parse --short HEAD)"
