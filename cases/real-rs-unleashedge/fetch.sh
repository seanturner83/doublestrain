#!/bin/sh
# Fetch the pinned Unleash Edge v19.9.1 checkout this case was labelled against.
# Read-only use: nothing is installed, built or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=304fe521e24551c68037e877192601485a413c7c
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/Unleash/unleash-edge.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
echo "real-rs-unleashedge at $(git -C repo rev-parse --short HEAD)"
