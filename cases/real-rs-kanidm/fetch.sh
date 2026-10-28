#!/bin/sh
# Fetch the pinned Kanidm v1.4.3 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=fb001765ae065d332aa5fef1e993f24998387dc3
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/kanidm/kanidm.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-rs-kanidm at $(git -C repo rev-parse --short HEAD)"
