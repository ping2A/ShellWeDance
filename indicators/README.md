# PowerShell detection indicators (psexposed format)

This directory contains **all** [psexposed](https://github.com/avasero/psexposed/tree/main/indicators) indicators (92 YAML files) from [avasero/psexposed](https://github.com/avasero/psexposed). The WASM analyzer **decodes** `-enc` / `-encodedcommand` (Base64 UTF-16LE) and matches indicators on both the raw command line and decoded script. Each indicator file has:

- **name** – short label
- **description** – optional longer description
- **regex** – pattern matched against the command line (Rust regex syntax)
- **basescore** – score added when the indicator matches (e.g. 4.5, 5.0, 10)
- **tactic** – MITRE ATT&CK tactic (e.g. TA0002 = Execution)
- **technique** – MITRE ATT&CK technique ID(s), string or list (e.g. T1059.001, T1027)
- **reference** – optional list of URLs

Some psexposed regexes use very deep nesting or PCRE-only features; the loader skips indicators whose regex fails to compile in Rust. `ps_indicator_plain_encoded_command.yaml` uses a Rust-compatible simplified pattern.

## Using indicators in the browser

From the repo root, copy YAMLs into `wasm/indicators/` and refresh `manifest.json`:

```bash
./scripts/generate_rules_yml.sh
```

Then build and serve the UI (see [README.md](../README.md) or [wasm/README.md](../wasm/README.md)).

## Updating indicators from upstream

```bash
git clone --depth 1 https://github.com/avasero/psexposed.git
cp psexposed/indicators/*.yaml ./indicators/
./scripts/generate_rules_yml.sh
```

## References

- [powershell.exposed](https://www.powershell.exposed/) – community-driven PowerShell detection  
- [psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators)  
