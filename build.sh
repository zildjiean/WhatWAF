#!/bin/sh
# Builds a clean zip for the Chrome Web Store with only the files the extension uses.
set -eu
cd "$(dirname "$0")"

VERSION=$(python3 -c 'import json;print(json.load(open("manifest.json"))["version"])')
OUT="dist/waf-detector-$VERSION.zip"

FILES="manifest.json background.js wafSignatures.js popup.html popup.js
icons/icon16.png icons/icon32.png icons/icon48.png icons/icon128.png"

for f in $FILES; do
  [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

mkdir -p dist
rm -f "$OUT"
# -X: no extra file attributes (no macOS metadata)
zip -X -q "$OUT" $FILES
echo "Built $OUT"
unzip -l "$OUT"
