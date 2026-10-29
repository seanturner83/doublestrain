#!/bin/sh
# Fetch the pinned kafbat kafka-ui 1.3.0 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=8b5494b67a1185fc334ee9fbb10e9acb51fa288a
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/kafbat/kafka-ui.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/kafbat/kafka-ui/releases/download/v1.3.0/api-v1.3.0.jar
SHA256=dec9bd8b08b02e286e5ba84e13b514471de3a7daaa925b67334feb5cfcc7955f
mkdir -p artifact
[ -f artifact/api-v1.3.0.jar ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/api-v1.3.0.jar.part "$ART" && mv artifact/api-v1.3.0.jar.part artifact/api-v1.3.0.jar; }
echo "$SHA256  artifact/api-v1.3.0.jar" | shasum -a 256 -c -
echo "real-jv-kafkaui at $(git -C repo rev-parse --short HEAD)"
