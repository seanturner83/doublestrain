#!/bin/sh
# Fetch the pinned netbox v3.7.8 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=be903a64a2f5e2b6d070ac40adbff13197656242
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/netbox-community/netbox.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-netbox at $(git -C repo rev-parse --short HEAD)"
