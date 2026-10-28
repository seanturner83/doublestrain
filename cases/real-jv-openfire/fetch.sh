#!/bin/sh
# Fetch the pinned Openfire 5.0.0 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=68a5d6b736c90996f1ac8dc9bf9bacf11d55f4a7
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/igniterealtime/Openfire.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/igniterealtime/Openfire/releases/download/v5.0.0/openfire_5_0_0.tar.gz
SHA256=9ca32b33f960e642fd502616726c51749fbf76678cbb0d097a12634356f10218
mkdir -p artifact
[ -f artifact/openfire_5_0_0.tar.gz ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/openfire_5_0_0.tar.gz.part "$ART" && mv artifact/openfire_5_0_0.tar.gz.part artifact/openfire_5_0_0.tar.gz; }
echo "$SHA256  artifact/openfire_5_0_0.tar.gz" | shasum -a 256 -c -
echo "real-jv-openfire at $(git -C repo rev-parse --short HEAD)"
