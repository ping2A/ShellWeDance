#!/bin/bash
# Build and test the WASM workspace (shell-we-dance-ps + wasm crate).

set -e
echo "Shell We Dance — workspace build"
echo ""

if ! command -v cargo &>/dev/null; then
  echo "Install Rust from https://rustup.rs"
  exit 1
fi

cargo test --workspace
cargo build --workspace --release

echo ""
echo "For the browser UI, install wasm-pack and run:"
echo "  ./scripts/run_wasm_ui.sh 8080"
echo ""
