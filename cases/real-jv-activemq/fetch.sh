#!/bin/sh
# Fetch the pinned Apache ActiveMQ Classic 6.1.7 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=2e94ec32cce6232212a66f090383e31b1c3fb772
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/apache/activemq.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://archive.apache.org/dist/activemq/6.1.7/apache-activemq-6.1.7-bin.tar.gz
SHA256=75cc41109a897745d44aca27358568f3cbe0cd58fc6bbff035a83c4ddf48d316
mkdir -p artifact
[ -f artifact/apache-activemq-6.1.7-bin.tar.gz ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/apache-activemq-6.1.7-bin.tar.gz.part "$ART" && mv artifact/apache-activemq-6.1.7-bin.tar.gz.part artifact/apache-activemq-6.1.7-bin.tar.gz; }
echo "$SHA256  artifact/apache-activemq-6.1.7-bin.tar.gz" | shasum -a 256 -c -
echo "real-jv-activemq at $(git -C repo rev-parse --short HEAD)"
