#!/bin/sh
# Fetch the pinned superset 4.0.2 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=f11fa091e261a35f4d39d8567a859fad07547d84
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/apache/superset.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-superset at $(git -C repo rev-parse --short HEAD)"
