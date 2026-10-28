#!/bin/sh
# Fetch the pinned Grafana OnCall v1.13.11 (engine/) checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=f8cd00b38fb15f40313b170d8a49edd100a497cf
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/grafana/oncall.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-oncall at $(git -C repo rev-parse --short HEAD)"
