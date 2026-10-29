#!/bin/sh
# Fetch the pinned GitBucket 4.43.0 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=d6217d89ebcd47721ed86841ea192cee48ce910a
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/gitbucket/gitbucket.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/gitbucket/gitbucket/releases/download/4.43.0/gitbucket.war
SHA256=c613573af7fa6ecc9a4ee5b98c8aef4bcdde08f78131d704d0ed9048abab2245
mkdir -p artifact
[ -f artifact/gitbucket.war ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/gitbucket.war.part "$ART" && mv artifact/gitbucket.war.part artifact/gitbucket.war; }
echo "$SHA256  artifact/gitbucket.war" | shasum -a 256 -c -
echo "real-jv-gitbucket at $(git -C repo rev-parse --short HEAD)"
