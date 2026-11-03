#!/bin/sh
# Fetch the pinned Metabase 0.55.8 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=b937b3e2c4051bb56f3c3e81c52c9f41528b223b
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/metabase/metabase.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://downloads.metabase.com/v0.55.8/metabase.jar
SHA256=216c17b279a6051fa66dc5cd4018ea81d691dcd4c90907161141b64f43795ec2
mkdir -p artifact
[ -f artifact/metabase.jar ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/metabase.jar.part "$ART" && mv artifact/metabase.jar.part artifact/metabase.jar; }
echo "$SHA256  artifact/metabase.jar" | shasum -a 256 -c -
echo "real-jv-metabase at $(git -C repo rev-parse --short HEAD)"
