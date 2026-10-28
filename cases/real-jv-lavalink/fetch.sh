#!/bin/sh
# Fetch the pinned Lavalink 4.1.1 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=4238202aea037fbe35da452c496b7d4f2ca74602
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/lavalink-devs/Lavalink.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/lavalink-devs/Lavalink/releases/download/4.1.1/Lavalink.jar
SHA256=651ff960381bce202a391f1f7b1dda333c9b3e62f2fca386b4d335d998ffb6d8
mkdir -p artifact
[ -f artifact/Lavalink.jar ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/Lavalink.jar.part "$ART" && mv artifact/Lavalink.jar.part artifact/Lavalink.jar; }
echo "$SHA256  artifact/Lavalink.jar" | shasum -a 256 -c -
echo "real-jv-lavalink at $(git -C repo rev-parse --short HEAD)"
