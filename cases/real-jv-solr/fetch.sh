#!/bin/sh
# Fetch the pinned Apache Solr 9.8.1 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=dab835e4a3249780230e5b1cefebffdf15ad5c96
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/apache/solr.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://archive.apache.org/dist/solr/solr/9.8.1/solr-9.8.1.tgz
SHA256=a789110131bc8cb71b0233d528e4fa5ffa566bab05bc72f280a8cc9275bd9e3e
mkdir -p artifact
[ -f artifact/solr-9.8.1.tgz ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/solr-9.8.1.tgz.part "$ART" && mv artifact/solr-9.8.1.tgz.part artifact/solr-9.8.1.tgz; }
echo "$SHA256  artifact/solr-9.8.1.tgz" | shasum -a 256 -c -
echo "real-jv-solr at $(git -C repo rev-parse --short HEAD)"
