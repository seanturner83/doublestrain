#!/bin/sh
# Fetch the pinned AKHQ 0.26.0 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=a39a1d0d4af145e9cd4f72399f919bb36b9900a0
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/tchiotludo/akhq.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/tchiotludo/akhq/releases/download/0.26.0/akhq-0.26.0-all.jar
SHA256=6e32226eb7e0d886d738c613d8e1b94486f8d400f020b66fe97b620d1de76fd8
mkdir -p artifact
[ -f artifact/akhq-0.26.0-all.jar ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/akhq-0.26.0-all.jar.part "$ART" && mv artifact/akhq-0.26.0-all.jar.part artifact/akhq-0.26.0-all.jar; }
echo "$SHA256  artifact/akhq-0.26.0-all.jar" | shasum -a 256 -c -
echo "real-jv-akhq at $(git -C repo rev-parse --short HEAD)"
