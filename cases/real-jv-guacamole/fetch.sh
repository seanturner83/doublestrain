#!/bin/sh
# Fetch the pinned Apache Guacamole 1.6.0 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=0537c89cd783681b986ff8f8c4e0b97ec6873371
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/apache/guacamole-client.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://archive.apache.org/dist/guacamole/1.6.0/binary/guacamole-1.6.0.war
SHA256=b41ceb1e2df010b54db563e0b00edb8d5fe9f073c6168462e4c978df0fc6e716
mkdir -p artifact
[ -f artifact/guacamole-1.6.0.war ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/guacamole-1.6.0.war.part "$ART" && mv artifact/guacamole-1.6.0.war.part artifact/guacamole-1.6.0.war; }
echo "$SHA256  artifact/guacamole-1.6.0.war" | shasum -a 256 -c -
echo "real-jv-guacamole at $(git -C repo rev-parse --short HEAD)"
