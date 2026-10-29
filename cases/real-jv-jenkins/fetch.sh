#!/bin/sh
# Fetch the pinned Jenkins 2.504.3 LTS checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=be8bec65854aa572bd2492c933c4ca77e4ac2db2
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/jenkinsci/jenkins.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://get.jenkins.io/war-stable/2.504.3/jenkins.war
SHA256=ea8883431b8b5ef6b68fe0e5817c93dc0a11def380054e7de3136486796efeb0
mkdir -p artifact
[ -f artifact/jenkins.war ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/jenkins.war.part "$ART" && mv artifact/jenkins.war.part artifact/jenkins.war; }
echo "$SHA256  artifact/jenkins.war" | shasum -a 256 -c -
echo "real-jv-jenkins at $(git -C repo rev-parse --short HEAD)"
