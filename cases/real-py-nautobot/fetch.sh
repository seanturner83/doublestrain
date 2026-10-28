#!/bin/sh
# Fetch the pinned Nautobot v2.3.16 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=c7dda3fe6c6d88e5efccf86040fd2440be16e9db
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/nautobot/nautobot.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-nautobot at $(git -C repo rev-parse --short HEAD)"
