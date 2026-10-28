#!/bin/sh
# Fetch the pinned CTFd 3.7.4 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=0d12a13d6a39d5b9dc21c5efd4e29c4ca05e6128
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/CTFd/CTFd.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-ctfd at $(git -C repo rev-parse --short HEAD)"
