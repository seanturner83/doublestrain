#!/bin/sh
# Fetch the pinned Stirling-PDF 0.46.2 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=70349fb7e32551b0afa9ba8c5ae3d85bfcc30e48
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/Stirling-Tools/Stirling-PDF.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/Stirling-Tools/Stirling-PDF/releases/download/v0.46.2/Stirling-PDF.jar
SHA256=8062b24ae248fc119a57dd7448bb0896a97fb01c719cd99546da84a0062cc8b5
mkdir -p artifact
[ -f artifact/Stirling-PDF.jar ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/Stirling-PDF.jar.part "$ART" && mv artifact/Stirling-PDF.jar.part artifact/Stirling-PDF.jar; }
echo "$SHA256  artifact/Stirling-PDF.jar" | shasum -a 256 -c -
echo "real-jv-stirling at $(git -C repo rev-parse --short HEAD)"
