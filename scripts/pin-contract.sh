#!/usr/bin/env bash
# Vendors identity's Principal contract at a ref (a tag such as contract/principal/v1.1.0, or a
# commit) into contract/, which the conformance tests read and the Principal type is generated from.
set -euo pipefail

ref=${1:?usage: pin-contract.sh <tag-or-commit>}
dest="$(cd "$(dirname "$0")/.." && pwd)/contract"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "https://codeload.github.com/JorisJonkers-dev/identity/tar.gz/$ref" | tar -xz -C "$tmp"
src=$(find "$tmp" -maxdepth 3 -type d -path '*/contract/principal' | head -1)
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$src/principal.schema.json" "$src/mapping.json" "$src/vectors" "$dest/"
echo "$ref" >"$dest/REF"
echo "pinned the Principal contract at $ref"
