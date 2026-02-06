//! PowerShell detection indicators (psexposed format).
//! See: https://github.com/avasero/psexposed/tree/main/indicators
//! and https://www.powershell.exposed/

use regex::Regex;
use regex::RegexBuilder;
use serde::Deserialize;
use std::path::Path;
use std::fs;
use std::io;
use anyhow::{Context, Result};

/// Raw YAML structure for a single psexposed indicator
#[derive(Debug, Clone, Deserialize)]
pub struct PsIndicatorYaml {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub regex: String,
    pub basescore: f64,
    /// Can be single string or array in YAML (e.g. tactic: TA0002 or tactic: [TA0007])
    #[serde(deserialize_with = "deser_tactic")]
    #[serde(default)]
    pub tactic: String,
    /// Can be single string or array in YAML
    #[serde(deserialize_with = "deser_technique")]
    #[serde(default)]
    pub technique: Vec<String>,
    #[serde(default)]
    pub reference: Vec<String>,
}

fn deser_tactic<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Tactic {
        One(String),
        Many(Vec<String>),
    }
    let t = Tactic::deserialize(deserializer)?;
    Ok(match t {
        Tactic::One(s) => s,
        Tactic::Many(v) => v.join(", "),
    })
}

fn deser_technique<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Tech {
        One(String),
        Many(Vec<String>),
    }
    let t = Tech::deserialize(deserializer)?;
    Ok(match t {
        Tech::One(s) => vec![s],
        Tech::Many(v) => v,
    })
}

/// Compiled indicator with pre-compiled regex for fast matching
#[derive(Debug, Clone)]
pub struct CompiledPsIndicator {
    pub name: String,
    pub description: String,
    pub basescore: f64,
    pub tactic: String,
    pub technique: Vec<String>,
    pub reference: Vec<String>,
    /// Original regex pattern (for display in UI)
    pub regex_pattern: String,
    pub regex: Regex,
}

impl PsIndicatorYaml {
    /// Compile the indicator regex and build a CompiledPsIndicator.
    /// Regex is compiled case-insensitively so decoded scripts (e.g. "IEX", "Net.WebClient") match.
    pub fn compile(self) -> Result<CompiledPsIndicator> {
        let regex = RegexBuilder::new(&self.regex)
            .case_insensitive(true)
            .build()
            .with_context(|| {
                format!("invalid regex in indicator '{}': {}", self.name, self.regex)
            })?;
        Ok(CompiledPsIndicator {
            name: self.name,
            description: self.description,
            basescore: self.basescore,
            tactic: self.tactic,
            technique: self.technique,
            reference: self.reference,
            regex_pattern: self.regex.clone(),
            regex,
        })
    }
}

/// Load all psexposed-format YAML indicators from a directory (non-recursive).
pub fn load_indicators_from_dir(dir: &Path) -> Result<Vec<CompiledPsIndicator>> {
    let (compiled, _) = load_indicators_from_dir_with_errors(dir)?;
    Ok(compiled)
}

/// Per-file load result for CLI debug: (filename, Ok(()) if loaded, Err(message) if failed).
pub type DirLoadResult = Vec<(String, Result<(), String>)>;

/// Like `load_indicators_from_dir` but also returns per-file success/failure for debug output.
pub fn load_indicators_from_dir_with_errors(
    dir: &Path,
) -> Result<(Vec<CompiledPsIndicator>, DirLoadResult), anyhow::Error> {
    let mut compiled = Vec::new();
    let mut results = DirLoadResult::new();
    let entries = fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "yaml" || e == "yml"))
        .collect();
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        match load_indicator_file(&path) {
            Ok(indicators) => {
                compiled.extend(indicators);
                results.push((name, Ok(())));
            }
            Err(e) => {
                let msg = e.to_string();
                tracing::warn!("skip {}: {}", path.display(), msg);
                results.push((name, Err(msg)));
            }
        }
    }
    Ok((compiled, results))
}

/// Load one YAML file; may contain a single indicator (one document) or multiple (multi-doc).
pub fn load_indicator_file(path: &Path) -> Result<Vec<CompiledPsIndicator>> {
    let content = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    load_indicators_from_str(&content)
}

/// Parse YAML content (single document) into compiled indicators.
pub fn load_indicators_from_str(content: &str) -> Result<Vec<CompiledPsIndicator>> {
    let yaml: PsIndicatorYaml = serde_yaml::from_str(content)
        .context("parsing indicator YAML")?;
    Ok(vec![yaml.compile()?])
}

/// Load indicators from multiple YAML strings. Each string may be a single document
/// or multiple documents separated by "---\n", so all 90+ indicators load correctly.
pub fn load_indicators_from_yaml_strings(contents: &[&str]) -> Result<Vec<CompiledPsIndicator>> {
    let (compiled, _) = load_indicators_from_yaml_strings_with_errors(contents);
    Ok(compiled)
}

/// Like `load_indicators_from_yaml_strings` but also returns per-rule load errors.
/// `errors` is `(rule_index, message)` for each document that failed to parse.
pub fn load_indicators_from_yaml_strings_with_errors(
    contents: &[&str],
) -> (Vec<CompiledPsIndicator>, Vec<(usize, String)>) {
    let mut compiled = Vec::new();
    let mut errors = Vec::new();
    let mut rule_index = 0usize;
    for content in contents {
        for doc in content.split("\n---") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            rule_index += 1;
            match load_indicators_from_str(doc) {
                Ok(indicators) => compiled.extend(indicators),
                Err(e) => {
                    let msg = e.to_string();
                    #[cfg(not(target_arch = "wasm32"))]
                    tracing::warn!("skip indicator YAML (index {}): {}", rule_index, msg);
                    errors.push((rule_index, msg));
                }
            }
        }
    }
    (compiled, errors)
}

/// Read command lines from stdin (one per line) or from a file.
pub fn read_command_lines(from: Option<&Path>) -> io::Result<Vec<String>> {
    use std::io::BufRead;
    let stdin = io::stdin();
    let reader: Box<dyn BufRead> = match from {
        None => Box::new(stdin.lock()),
        Some(p) => Box::new(io::BufReader::new(fs::File::open(p)?)),
    };
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deser_technique_single() {
        let yaml = r#"
name: Test
regex: "foo"
basescore: 1.0
tactic: TA0002
technique: T1059.001
"#;
        let y: PsIndicatorYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(y.technique, vec!["T1059.001"]);
    }

    #[test]
    fn test_deser_technique_many() {
        let yaml = r#"
name: Test
regex: "bar"
basescore: 2.0
technique: [T1059.001, T1027]
"#;
        let y: PsIndicatorYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(y.technique, vec!["T1059.001", "T1027"]);
    }
}
