#!/bin/sh
# Fetch the pinned authentik 2024.6.4 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=8a0b31b9227ca33b96c5448f185419f17090ed38
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/goauthentik/authentik.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-authentik at $(git -C repo rev-parse --short HEAD)"
