#!/bin/sh
# Fetch the pinned SirAppSec/vuln-node.js-express.js-app checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=b977c7407f328da929577745ad509639e26c428a
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/SirAppSec/vuln-node.js-express.js-app.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-sirappsec-vuln at $(git -C repo rev-parse --short HEAD)"
