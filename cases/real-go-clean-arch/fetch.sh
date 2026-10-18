#!/bin/sh
# Fetch the pinned bxcodec/go-clean-arch checkout this case was labelled against.
# Read-only use: nothing is built, installed or executed (govulncheck type-checks it, sandboxed).
set -eu
cd "$(dirname "$0")"
COMMIT=e06c6d0cb37069b0ef56e3df67f80ca130a1ab82
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/bxcodec/go-clean-arch.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-go-clean-arch at $(git -C repo rev-parse --short HEAD)"
