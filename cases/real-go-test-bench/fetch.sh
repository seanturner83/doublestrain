#!/bin/sh
# Fetch the pinned Contrast-Security-OSS/go-test-bench checkout this case was labelled against.
# Read-only use: nothing is built, installed or executed (govulncheck type-checks it, sandboxed).
set -eu
cd "$(dirname "$0")"
COMMIT=92445700823205281369911a72b7127f18c8c9ed
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/Contrast-Security-OSS/go-test-bench.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-go-test-bench at $(git -C repo rev-parse --short HEAD)"
