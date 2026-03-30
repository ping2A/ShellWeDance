#!/usr/bin/env bash
# Inject wasm/indicators/rules.yml into wasm/index.html so rules are loaded directly from the index (no request).
# Run from repo root after: ./scripts/generate_rules_yml.sh

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES_FILE="$REPO_ROOT/wasm/indicators/rules.yml"
INDEX_FILE="$REPO_ROOT/wasm/index.html"

if [ ! -f "$RULES_FILE" ]; then
  echo "Run ./scripts/generate_rules_yml.sh first to create $RULES_FILE"
  exit 1
fi

python3 - "$INDEX_FILE" "$RULES_FILE" << 'PY'
import html
import sys
index_path, rules_path = sys.argv[1], sys.argv[2]
with open(rules_path) as f:
    content = f.read()
escaped = html.escape(content)
with open(index_path) as f:
    html_content = f.read()
old = '<script type="text/yaml" id="indicators-rules"></script>'
new = f'<script type="text/yaml" id="indicators-rules">\n{escaped}\n</script>'
if old not in html_content:
    sys.exit("Placeholder not found in index.html")
html_content = html_content.replace(old, new, 1)
with open(index_path, "w") as f:
    f.write(html_content)
print(f"Injected rules into {index_path}")
PY
