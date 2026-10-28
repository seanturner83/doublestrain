#!/bin/sh
# Fetch the pinned Keycloak 26.1.4 checkout and release artifact this case was labelled against.
# Read-only use: nothing is installed, built or executed. The artifact is read as data
# (its jars are the deployed classpath, doublestrain/jvmjars.py).
set -eu
cd "$(dirname "$0")"
COMMIT=b281b5f09d06a55c661d8df529f0020dd44942d1
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/keycloak/keycloak.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
# submodules at the commits the superproject pins (https only: .gitmodules is untrusted data)
git -c protocol.allow=never -c protocol.https.allow=always -C repo submodule update -q --init --depth 1
ART=https://github.com/keycloak/keycloak/releases/download/26.1.4/keycloak-26.1.4.tar.gz
SHA256=db50b1286da510dea3f50d1c4f9128354d57065e805bd4b1bd1b456773b065c9
mkdir -p artifact
[ -f artifact/keycloak-26.1.4.tar.gz ] || { curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize 600000000 -o artifact/keycloak-26.1.4.tar.gz.part "$ART" && mv artifact/keycloak-26.1.4.tar.gz.part artifact/keycloak-26.1.4.tar.gz; }
echo "$SHA256  artifact/keycloak-26.1.4.tar.gz" | shasum -a 256 -c -
echo "real-jv-keycloak at $(git -C repo rev-parse --short HEAD)"
