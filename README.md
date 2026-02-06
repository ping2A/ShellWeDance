
<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Shell We Dance</h2>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
[![License: APACHE 2.0](https://img.shields.io/badge/License-APACHE_2.0-2596be.svg?style=for-the-badge)](LICENSE)

</div>

<br>

# Shell We Dance

**ShellWeDance** is a Rust project for **PowerShell command-line analysis** using [psexposed](https://github.com/avasero/psexposed)-style indicators. It scores and matches command lines (and decoded `-EncodedCommand` content) against YAML indicators (regex + basescore + MITRE ATT&CK). The same codebase also provides **Sigma rule evaluation** against JSON logs via the `sigma_zero` library and CLI.

Indicators are based on the [psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators) format. See [powershell.exposed](https://www.powershell.exposed/) for the online demo.

## Features

- **PowerShell analysis** (`shell-we-dance`): Score and analyze PowerShell command lines using [psexposed](https://github.com/avasero/psexposed)-style indicators (regex + basescore + tactic/technique). This repo ships with 92+ indicators in `./indicators`.
- **Base64 decoding**: Automatically decodes `-enc` / `-encodedcommand` (Base64 UTF-16LE) and shows the decoded script; matching runs on both the raw command line and the decoded content.
- **Sigma on decoded content** (optional): Run Sigma rules on the **decoded** script when `--sigma-rules-dir` is set.
- **WASM UI**: Browser app that loads indicators at runtime, shows severity (Clean / Low / Medium / High / Critical), match table, and which rules failed to load (if any). See [wasm/README.md](wasm/README.md).
- **Sigma rule evaluation** (`sigma-zero`): Evaluate Sigma detection rules against JSON/JSONL logs; streaming mode and correlation rules supported.
- **Output**: Text, JSON, or JSONL; parallel processing with Rayon; per-file load status in CLI.

## Installation

### Prerequisites
- Rust 1.70+ ([rustup](https://rustup.rs))

### Build from source

```bash
git clone https://github.com/ping2A/ShellWeDance
cd ShellWeDance

# Run without installing
cargo run --bin shell-we-dance -- -r ./indicators -c "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA="
cargo run --bin sigma-zero -- --rules-dir /path/to/sigma-rules --logs ./examples/logs

# Or build release binaries
cargo build --release
# Binaries: target/release/shell-we-dance, target/release/sigma-zero, target/release/sigma-zero-streaming, target/release/sigma-generate-logs
./target/release/shell-we-dance -r ./indicators -c "powershell ..."
./target/release/sigma-zero --rules-dir /path/to/sigma-rules --logs ./examples/logs
```

## Usage

### PowerShell command-line analysis (`shell-we-dance`)

Analyze PowerShell command lines using [psexposed](https://github.com/avasero/psexposed)-style indicators. The tool **decodes** `-enc` / `-encodedcommand` (Base64 UTF-16LE) and matches against both the raw command line and the decoded content. Optionally run **Sigma rules on the decoded script** with `--sigma-rules-dir`:

```bash
# Single command (decoded content shown when -enc is present)
cargo run --bin shell-we-dance -- -r ./indicators -c "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA="

# With Sigma rules on decoded content (optional)
cargo run --bin shell-we-dance -- -r ./indicators --sigma-rules-dir /path/to/sigma-rules -c "powershell -enc ..."

# From file (one command per line) or stdin
cargo run --bin shell-we-dance -- -r ./indicators -f commands.txt --format json
echo "powershell iex (Get-Content x.ps1)" | cargo run --bin shell-we-dance -- -r ./indicators
```

This repo ships with **92+ indicators** in `./indicators` (format compatible with [psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators)). The CLI prints per-file load status (`[ok]` / `[FAIL]`) when loading indicators. See `indicators/README.md` for indicator format.

**Options:** `-r, --indicators-dir` (indicator YAMLs), `--sigma-rules-dir` (optional Sigma rules for decoded content), `-c, --command` (command line, repeatable), `-f, --file` (one command per line), `--format text|json|jsonl`, `--min-score`, `-v, --verbose`.

### WASM (browser)

A browser build runs the same analyzer: paste a PowerShell command and see indicator matches, decoded `-EncodedCommand` content, severity (Clean / Low / Medium / High / Critical), and a match table. Indicators are loaded at runtime from `wasm/indicators/`; the UI shows which rules failed to load (if any). The footer links to the [original psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators) and to [ShellWeDance](https://github.com/ping2A/ShellWeDance).

```bash
wasm-pack build wasm --out-dir wasm/pkg --target web
cd wasm && python3 -m http.server 8080
# Open http://localhost:8080
```

See [wasm/README.md](wasm/README.md) for build and run details.

### Sigma rule evaluation (`sigma-zero`)

This repo also includes the **sigma-zero** CLI for evaluating Sigma detection rules against JSON/JSONL logs:

```bash
cargo run --bin sigma-zero -- --rules-dir /path/to/sigma-rules --logs /path/to/logs
```

Options: `-r, --rules-dir`, `-l, --logs`, `-c, --correlation-rules`, `-w, --workers`, `-o, --output`, `-f, --format`, `--validate`, `--filter-tag`, `--filter-level`, `--filter-id`, `--field-map`, `-v, --verbose`. Run `sigma-zero --help` for full usage.

### Sigma-zero examples

```bash
# Single log file
cargo run --bin sigma-zero -- -r /path/to/rules -l ./logs/security.json

# JSON output, 8 workers
cargo run --bin sigma-zero -- -r ./rules -l ./logs -f json -o matches.json -w 8

# Validate rules only
cargo run --bin sigma-zero -- -r ./rules --validate

# Filter by tag/level
cargo run --bin sigma-zero -- -r ./rules -l ./logs --filter-tag attack.execution --filter-level high
```

### Streaming mode (`sigma-zero-streaming`)

For real-time or pipe-based evaluation, use **sigma-zero-streaming**. It reads JSON logs from stdin and evaluates them as they arrive:

```bash
# With cargo
tail -f /var/log/app.json | cargo run --bin sigma-zero-streaming -- -r ./rules
journalctl -f -o json | cargo run --bin sigma-zero-streaming -- -r ./rules

# Or after cargo build --release
tail -f /var/log/app.json | sigma-zero-streaming -r ./rules
```

**Streaming options:**
- `-r, --rules-dir` – Path to Sigma rules
- `-c, --correlation-rules` – Optional correlation rules directory
- `-b, --batch-size <N>` – Process logs in batches of N (default: 1 for real-time)
- `-f, --output-format <json|text|silent>` – Output format (default: text)
- `-m, --min-level <LEVEL>` – Only output matches at or above this level (low, medium, high, critical)

**Throughput:** Use a larger batch size (e.g. `-b 100`) to trade latency for higher throughput when reading from a pipe or file.

## Log Format

Logs must be in JSON format with one log entry per line (JSONL). Each log entry should be a JSON object with arbitrary fields:

```json
{
  "timestamp": "2025-11-06T10:15:30Z",
  "event_type": "process_creation",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
  "user": "john.doe",
  "source_ip": "192.168.1.50"
}
```

## Sigma Rule Format

Rules follow the standard Sigma format. Here's an example:

```yaml
title: Suspicious Process Execution
id: 12345678-1234-1234-1234-123456789abc
description: Detects execution of suspicious processes
status: experimental
level: high
detection:
  selection:
    process_name:
      - '*powershell.exe'
      - '*cmd.exe'
      - '*mimikatz*'
    command_line:
      - '*-enc*'
      - '*bypass*'
  condition: selection
tags:
  - attack.execution
  - attack.t1059
```

### Supported Features

- **Field matching**: Exact match, substring match, wildcard (*) support
- **Field modifiers**: 
  - `startswith` - Match values that start with pattern
  - `endswith` - Match values that end with pattern
  - `contains` - Match values containing pattern (default)
  - `all` - Require all values to match (instead of any)
  - `re` - Regular expression matching
  - `base64` - Match base64-decoded content
  - `lt/lte/gt/gte` - Numeric comparisons
- **Advanced Conditions**:
  - `AND` - All conditions must match
  - `OR` - At least one condition must match
  - `NOT` - Negate/exclude conditions
  - Parentheses `()` for grouping
  - `1 of them`, `all of them` - Pattern-based selection
  - `1 of selection_*` - Wildcard selection matching
  - **Threshold/count conditions**: `selection_name | count > 5` or `| count >= N` – rule fires when the number of logs matching the selection (in the current batch) satisfies the threshold. Evaluated only in batch mode (file or `evaluate_log_batch`).

📖 **See [CONDITION_OPERATORS.md](docs/CONDITION_OPERATORS.md) for complete documentation on all operators and modifiers.**
- **Multiple values**: Arrays of values for OR logic
- **Conditions**: 
  - Single selection
  - AND conditions (all selections must match)
  - OR conditions (at least one selection must match)
- **Wildcards**: Use `*` for wildcard matching (e.g., `*powershell*`)

**See [FIELD_MODIFIERS.md](docs/FIELD_MODIFIERS.md) for complete field modifier documentation.**

### Example Rules Included

1. **suspicious_process.yml**: Detects suspicious process executions like PowerShell with encoded commands
2. **suspicious_network.yml**: Detects connections to known malicious domains or suspicious IPs
3. **privilege_escalation.yml**: Detects privilege escalation attempts
4. **modifiers_startswith.yml**: Demonstrates startswith modifier usage
5. **modifiers_endswith.yml**: Demonstrates endswith modifier for file extensions
6. **modifiers_regex.yml**: Demonstrates regex pattern matching
7. **modifiers_all.yml**: Demonstrates all modifier for multi-condition matching
8. **modifiers_base64.yml**: Demonstrates base64 content detection
9. **modifiers_comparison.yml**: Demonstrates numeric comparison operators

### Example Log Files Included

The project includes 4 realistic security log files (170 total events):

1. **security_events.json** (15 events) - Basic security events with mixed legitimate and suspicious activity
2. **critical_security_events.json** (50 events) - Comprehensive attack lifecycle from initial compromise to ransomware
3. **apt_attack_chain.json** (50 events) - Advanced Persistent Threat multi-stage attack campaign
4. **mixed_traffic.json** (55 events) - Realistic mix of legitimate (70%) and malicious (30%) traffic for false positive testing

**Attack Coverage**: All 12 MITRE ATT&CK tactics represented  
**Use Cases**: Development, testing, training, incident response simulation

## Performance Considerations

### Parallel Processing
The engine automatically uses all available CPU cores. You can control this with the `-w` flag:

```bash
# Use 16 workers for maximum throughput on a 16+ core system
sigma-zero -r ./rules -l ./huge-logs -w 16
```

### Memory Efficiency
- Logs are streamed line-by-line to minimize memory usage
- Parsed logs are processed in batches
- Results are collected incrementally

### Optimization Tips
1. **Compile in release mode**: Always use `cargo build --release`
2. **Adjust worker count**: Match to your CPU core count for best results
3. **Use SSD storage**: Faster disk I/O significantly improves performance
4. **Rule optimization**: More specific rules (fewer wildcards) evaluate faster

## Benchmarking

To benchmark performance on your system:

```bash
# Create a large test log file
seq 1 1000000 | while read i; do 
  echo "{\"id\": $i, \"process_name\": \"test.exe\", \"command_line\": \"test command $i\"}"
done > large_test.json

# Time the evaluation
time sigma-zero -r /path/to/rules -l large_test.json -w $(nproc)
```

## Output Format

Matches are output in JSON format:

```json
{
  "rule_id": "12345678-1234-1234-1234-123456789abc",
  "rule_title": "Suspicious Process Execution",
  "level": "high",
  "matched_log": {
    "timestamp": "2025-11-06T10:15:30Z",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -enc ...",
    "user": "john.doe"
  },
  "timestamp": "2025-11-06T12:30:45.123Z"
}
```

## Limitations

- **Condition complexity**: Complex condition expressions with nested parentheses and NOT operators are simplified
- **Aggregation**: Time-based aggregations and correlations not yet supported
- **Field modifiers**: Most common modifiers implemented (startswith, endswith, contains, all, re, base64, comparisons). Advanced modifiers like utf16le/utf16be are planned for future releases

## Resources

- **[psexposed indicators](https://github.com/avasero/psexposed/tree/main/indicators)** — Original indicator format and community rules
- **[powershell.exposed](https://www.powershell.exposed/)** — Online demo of psexposed-style analysis
- **[Sigma](https://github.com/SigmaHQ/sigma)** — Sigma rule format
- **[MITRE ATT&CK](https://attack.mitre.org/)** — Tactics and techniques


## About

**ShellWeDance** focuses on PowerShell command-line analysis using [psexposed](https://github.com/avasero/psexposed)-style indicators (regex + score + MITRE ATT&CK). The same repo includes the **sigma-zero** engine and CLIs for evaluating Sigma rules against JSON logs, so you can use it as a small local SIEM or to score specific logs and command lines.

