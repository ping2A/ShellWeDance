# Shell We Dance — WASM (browser)

PowerShell command-line analyzer in the browser: paste a command, get indicator matches and decoded `-EncodedCommand` content. Indicators are loaded at runtime by requesting each rule file individually from `indicators/`.

## Build

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```bash
# From repo root
wasm-pack build wasm --out-dir wasm/pkg --target web
```

## Generate indicator files and manifest

The UI fetches `indicators/manifest.json` then requests each file listed there (e.g. `indicators/ps_indicator_foo.yaml`). Generate from the repo indicators:

```bash
# From repo root
./scripts/generate_rules_yml.sh
# Copies indicators/*.yaml to wasm/indicators/ and writes wasm/indicators/manifest.json
```

## Run

Serve the **wasm** directory over HTTP (required for ES modules, WASM, and the indicator requests). For example:

```bash
cd wasm && python3 -m http.server 8080
# or: npx serve wasm -p 8080
```

Open [http://localhost:8080](http://localhost:8080). The page fetches the manifest, then each rule file, loads indicators, then you can paste a PowerShell command and click **Analyze**.

## Debug

Open the browser console (F12 → Console). With debug enabled you’ll see `[ShellWeDance]` logs for: init, WASM load, manifest fetch, each rule fetch (e.g. `fetch rule { i, total, name }`), indicator count, and each analyze (result summary).
</think><｜tool▁call▁begin｜>
TodoWrite
