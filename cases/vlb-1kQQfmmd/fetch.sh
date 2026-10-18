#!/bin/sh
# Fetch the pinned cypress-io/request checkout (@cypress/request 2.88.11) this case was
# labelled against: the vuln-bench copy is this upstream commit, unmodified.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=c5bcf21d40fb61feaff21a0e5a2b3934a440024f
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/cypress-io/request.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "vlb-1kQQfmmd at $(git -C repo rev-parse --short HEAD)"
