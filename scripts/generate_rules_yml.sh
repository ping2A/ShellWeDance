#!/usr/bin/env bash
# Copy each indicator YAML to wasm/indicators/ and write manifest.json (list of filenames).
# The UI fetches manifest.json then requests each file individually.
# Run from repo root.

set -e
INDICATORS_DIR="$(cd "$(dirname "$0")/.." && pwd)/indicators"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/wasm/indicators"

mkdir -p "$OUT_DIR"
manifest_file="$OUT_DIR/manifest.json"
count=0
first=1
echo -n '[' > "$manifest_file"
for f in "$INDICATORS_DIR"/*.yaml "$INDICATORS_DIR"/*.yml; do
  [ -f "$f" ] || continue
  name=$(basename "$f")
  cp "$f" "$OUT_DIR/$name"
  [ "$first" -eq 0 ] && echo -n ',' >> "$manifest_file"
  first=0
  printf '%s' "\"${name}\"" >> "$manifest_file"
  count=$((count + 1))
done
echo ']' >> "$manifest_file"
echo "Wrote $manifest_file ($count files) and copied indicator YAMLs to $OUT_DIR"
