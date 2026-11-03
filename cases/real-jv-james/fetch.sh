#!/bin/sh
# Fetch the pinned Apache James 3.8.2 (JPA Guice) checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=8d0e75ff1de1e378c853f9d5075d6ffe1ce9446a
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/apache/james-project.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://archive.apache.org/dist/james/server/3.8.2/james-server-jpa-guice.zip
SHA256=c850bc193cad96e36187c1ed7293022aad260ffef9df5035478c7cbfd7538d42
mkdir -p artifact
[ -f artifact/james-server-jpa-guice.zip ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/james-server-jpa-guice.zip.part "$ART" && mv artifact/james-server-jpa-guice.zip.part artifact/james-server-jpa-guice.zip; }
echo "$SHA256  artifact/james-server-jpa-guice.zip" | shasum -a 256 -c -
echo "real-jv-james at $(git -C repo rev-parse --short HEAD)"
