#!/usr/bin/env bash
# Build the browser WASM package (PowerShell analyzer only, no Sigma engine) and serve wasm/.
# Usage: ./scripts/run_wasm_ui.sh [PORT]
# Default PORT=8080. Open http://localhost:PORT/

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${1:-8080}"

cd "$ROOT"

if ! command -v wasm-pack &>/dev/null; then
  echo "wasm-pack is required: https://rustwasm.github.io/wasm-pack/installer/"
  exit 1
fi

echo "Building WASM (release)…"
wasm-pack build wasm --release --out-dir pkg --target web

echo "Refreshing wasm/indicators manifest…"
bash scripts/generate_rules_yml.sh

echo "Serving ${ROOT}/wasm at http://127.0.0.1:${PORT}/ (Ctrl+C to stop)"
cd "${ROOT}/wasm"
exec python3 -m http.server "${PORT}"
