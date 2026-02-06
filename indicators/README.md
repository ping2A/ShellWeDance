# PowerShell Detection Indicators (psexposed format)

This directory contains **all** [psexposed](https://github.com/avasero/psexposed/tree/main/indicators) indicators (92 YAML files) from [avasero/psexposed](https://github.com/avasero/psexposed). The analyzer **decodes** `-enc` / `-encodedcommand` (Base64 UTF-16LE) and can optionally run Sigma rules on the decoded content with `--sigma-rules-dir`. Each indicator file has:

- **name** – short label
- **description** – optional longer description
- **regex** – pattern matched against the command line (Rust regex syntax)
- **basescore** – score added when the indicator matches (e.g. 4.5, 5.0, 10)
- **tactic** – MITRE ATT&CK tactic (e.g. TA0002 = Execution)
- **technique** – MITRE ATT&CK technique ID(s), string or list (e.g. T1059.001, T1027)
- **reference** – optional list of URLs

Some psexposed regexes use very deep nesting or PCRE-only features; the loader skips indicators whose regex fails to compile in Rust (with a warning). `ps_indicator_plain_encoded_command.yaml` uses a Rust-compatible simplified pattern.

## Updating indicators

This project ships with all psexposed indicators. To refresh from upstream:

```bash
git clone --depth 1 https://github.com/avasero/psexposed.git
cp psexposed/indicators/*.yaml ./indicators/
```

## Examples (with cargo)

```bash
# Single command (decoded content shown when -enc is present)
cargo run --bin shell-we-dance -- -r ./indicators -c "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA="

# With Sigma rules on decoded content (optional; use your own Sigma rules directory)
cargo run --bin shell-we-dance -- -r ./indicators --sigma-rules-dir /path/to/sigma-rules -c "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA="

# From file (one command per line)
cargo run --bin shell-we-dance -- -r ./indicators -f commands.txt --format json

# From stdin
echo "powershell iex (Get-Content x.ps1)" | cargo run --bin shell-we-dance -- -r ./indicators
```

After `cargo build --release`, you can use the binary directly: `./target/release/shell-we-dance -r ./indicators -c "..."`.

## References

- [powershell.exposed](https://www.powershell.exposed/) – community-driven PowerShell detection
- [psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators)
- [Sigma rules (PowerShell)](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation)
