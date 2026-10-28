#!/bin/sh
# Fetch the pinned Tandoor Recipes 1.5.35 checkout this case was labelled against.
# Read-only use: nothing is installed or executed.
set -eu
cd "$(dirname "$0")"
COMMIT=cd2c4b35df6f3aafa957a02a515c0a9d0a33fe97
[ -d repo/.git ] || git clone -q --filter=blob:none https://github.com/TandoorRecipes/recipes.git repo
git -C repo fetch -q --depth 1 origin "$COMMIT"
git -C repo checkout -q "$COMMIT"
echo "real-py-tandoor at $(git -C repo rev-parse --short HEAD)"
