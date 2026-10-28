#!/bin/sh
# Fetch the pinned Traccar 6.8.0 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=b0eae5b83703a1dae8e441879f51cfc4fecfcd21
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/traccar/traccar.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/traccar/traccar/releases/download/v6.8.0/traccar-other-6.8.0.zip
SHA256=607e728c528bb061a43283fe011cf65c9c2eb6d76e9f484418bad53778277780
mkdir -p artifact
[ -f artifact/traccar-other-6.8.0.zip ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/traccar-other-6.8.0.zip.part "$ART" && mv artifact/traccar-other-6.8.0.zip.part artifact/traccar-other-6.8.0.zip; }
echo "$SHA256  artifact/traccar-other-6.8.0.zip" | shasum -a 256 -c -
echo "real-jv-traccar at $(git -C repo rev-parse --short HEAD)"
