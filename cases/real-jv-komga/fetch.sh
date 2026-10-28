#!/bin/sh
# Fetch the pinned Komga 1.21.3 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=45363fce3530e60a83c38b881fb8a7ba5ae04ce6
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/gotson/komga.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/gotson/komga/releases/download/1.21.3/komga-1.21.3.jar
SHA256=3458ff0b5a0d461f4fcc08b94d4bfee2f55e6b536c9ff7ebc5fe1a663b987ef0
mkdir -p artifact
[ -f artifact/komga-1.21.3.jar ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/komga-1.21.3.jar.part "$ART" && mv artifact/komga-1.21.3.jar.part artifact/komga-1.21.3.jar; }
echo "$SHA256  artifact/komga-1.21.3.jar" | shasum -a 256 -c -
echo "real-jv-komga at $(git -C repo rev-parse --short HEAD)"
