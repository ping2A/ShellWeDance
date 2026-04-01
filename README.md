
<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Shell We Dance</h2>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
[![License: APACHE 2.0](https://img.shields.io/badge/License-APACHE_2.0-2596be.svg?style=for-the-badge)](LICENSE)

</div>

<br>

# Shell We Dance

**ShellWeDance** is a **browser-based PowerShell command-line analyzer**. It scores pasted commands against [psexposed](https://github.com/avasero/psexposed)-style YAML indicators (regex + basescore + MITRE ATT&CK), decodes `-enc` / `-EncodedCommand` (Base64 UTF-16LE), and shows severity plus a match table. The engine is **Rust compiled to WebAssembly** (`shell-we-dance-ps` + `wasm/`).

Indicators match the [psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators) format. See [powershell.exposed](https://www.powershell.exposed/) for a related online demo.

## Features

- **WASM UI**: Load indicators over HTTP, analyze in the browser, see Clean / Low / Medium / High / Critical and per-rule load errors if any.
- **`-EncodedCommand` decoding**: Same matching on raw line and decoded script when `-enc` is present.
- **92+ indicators** in `./indicators` (copied into `wasm/indicators/` for the UI via `scripts/generate_rules_yml.sh`).

## Quick start (local)

**Prerequisites:** [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```bash
./scripts/run_wasm_ui.sh 8080
# Open http://localhost:8080
```

Or manually:

```bash
wasm-pack build wasm --release --out-dir pkg --target web
./scripts/generate_rules_yml.sh
cd wasm && python3 -m http.server 8080
```

See [wasm/README.md](wasm/README.md) for details.

## Docker

```bash
docker build -t shell-we-dance .
docker run -p 8080:80 shell-we-dance
# http://localhost:8080 — static UI + pkg/*.wasm + indicators/
```

## Development

```bash
cargo test --workspace
cargo build --workspace
```

Indicator YAML format and fields are described in [indicators/README.md](indicators/README.md).

## Resources

- **[psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators)** — Rule format and upstream rules  
- **[powershell.exposed](https://www.powershell.exposed/)** — Related PowerShell analysis demo  
- **[MITRE ATT&CK](https://attack.mitre.org/)** — Tactics and techniques referenced in rules  

## About

**ShellWeDance** ships a WASM-first PowerShell analyzer for local or containerized use, without a native CLI in this repository.
