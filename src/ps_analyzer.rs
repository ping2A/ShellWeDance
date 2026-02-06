//! PowerShell command-line analyzer using psexposed-style indicators.
//! Optionally decodes -enc/-encodedcommand and evaluates decoded content with Sigma rules.

use serde::Serialize;

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
use crate::engine::SigmaEngine;
#[cfg(not(target_arch = "wasm32"))]
use crate::models::LogEntry;
use crate::ps_decode::decode_encoded_command;
use crate::ps_indicator::{
    load_indicators_from_yaml_strings_with_errors, load_indicators_from_yaml_strings,
    CompiledPsIndicator,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::ps_indicator::{
    load_indicators_from_dir, load_indicators_from_dir_with_errors, DirLoadResult,
};

/// A single indicator match on a command line and/or decoded content
#[derive(Debug, Clone, Serialize)]
pub struct PsMatch {
    pub indicator_name: String,
    pub basescore: f64,
    pub tactic: String,
    pub technique: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_substring: Option<String>,
    /// Where this matched: "command_line" or "decoded" (when -enc was decoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_against: Option<String>,
}

/// Summary of a Sigma rule match (decoded content analysis)
#[derive(Debug, Clone, Serialize)]
pub struct SigmaMatchInfo {
    pub rule_id: Option<String>,
    pub rule_title: String,
    pub level: Option<String>,
}

/// Full indicator metadata for display in UI (name, description, regex, score, tactic, technique).
#[derive(Debug, Clone, Serialize)]
pub struct IndicatorInfo {
    pub name: String,
    pub description: String,
    pub regex: String,
    pub basescore: f64,
    pub tactic: String,
    pub technique: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reference: Vec<String>,
}

/// Result of analyzing one command line
#[derive(Debug, Clone, Serialize)]
pub struct PsAnalysisResult {
    /// Original command line (or truncated for output)
    pub command_line: String,
    /// All psexposed indicator matches
    pub matches: Vec<PsMatch>,
    /// Sum of basescores of all matched indicators
    pub total_score: f64,
    /// Whether any indicator matched
    pub is_suspicious: bool,
    /// Decoded script when -enc/-encodedcommand was present (truncated for output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_content: Option<String>,
    /// Sigma rule matches on the decoded content (when decoding succeeded and Sigma rules loaded)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sigma_matches: Vec<SigmaMatchInfo>,
}

/// Engine that evaluates PowerShell command lines against psexposed indicators
/// and optionally against Sigma rules on decoded -enc content
pub struct PsAnalyzer {
    indicators: Vec<CompiledPsIndicator>,
    #[cfg(not(target_arch = "wasm32"))]
    sigma_engine: Option<SigmaEngine>,
}

impl PsAnalyzer {
    /// Build analyzer from a directory of psexposed YAML indicator files only
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_dir(dir: &Path) -> anyhow::Result<Self> {
        let indicators = load_indicators_from_dir(dir)?;
        Ok(Self {
            indicators,
            sigma_engine: None,
        })
    }

    /// Like `from_dir` but returns per-file load results for CLI debug (success/failure per rule file).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_dir_with_errors(dir: &Path) -> anyhow::Result<(Self, DirLoadResult)> {
        let (indicators, results) = load_indicators_from_dir_with_errors(dir)?;
        Ok((
            Self {
                indicators,
                sigma_engine: None,
            },
            results,
        ))
    }

    /// Build analyzer from in-memory YAML strings (one indicator document per string).
    /// Used by WASM when indicators are embedded or passed from JS.
    pub fn from_yaml_strings(yaml_strings: &[&str]) -> anyhow::Result<Self> {
        let indicators = load_indicators_from_yaml_strings(yaml_strings)?;
        Ok(Self {
            indicators,
            #[cfg(not(target_arch = "wasm32"))]
            sigma_engine: None,
        })
    }

    /// Like `from_yaml_strings` but returns per-rule load errors (index, message) for documents that failed to parse.
    pub fn from_yaml_strings_with_errors(
        yaml_strings: &[&str],
    ) -> (Self, Vec<(usize, String)>) {
        let (indicators, errors) = load_indicators_from_yaml_strings_with_errors(yaml_strings);
        let analyzer = Self {
            indicators,
            #[cfg(not(target_arch = "wasm32"))]
            sigma_engine: None,
        };
        (analyzer, errors)
    }

    /// Build analyzer with both psexposed indicators and Sigma rules.
    /// Decoded -enc content is evaluated against Sigma rules (log field: CommandLine).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_dirs(indicators_dir: &Path, sigma_rules_dir: &Path) -> anyhow::Result<Self> {
        let indicators = load_indicators_from_dir(indicators_dir)?;
        let mut sigma_engine = SigmaEngine::new(None);
        sigma_engine.load_rules(sigma_rules_dir)?;
        Ok(Self {
            indicators,
            sigma_engine: Some(sigma_engine),
        })
    }

    /// Analyze a single command line; returns indicator matches (on raw + decoded when -enc present), optional decoded content, and Sigma matches on decoded content
    pub fn analyze(&self, command_line: &str) -> PsAnalysisResult {
        let mut matches = self.run_indicators(command_line, Some("command_line"));
        let decoded = decode_encoded_command(command_line);
        let decoded_content = decoded
            .as_ref()
            .map(|s| truncate_for_display(s, 2000));

        // Run the same indicators on decoded content; add matches we don't already have (by indicator name)
        if let Some(ref dec) = decoded {
            if !dec.is_empty() {
                let decoded_matches = self.run_indicators(dec, Some("decoded"));
                let existing: std::collections::HashSet<String> =
                    matches.iter().map(|m| m.indicator_name.clone()).collect();
                for m in decoded_matches {
                    if !existing.contains(&m.indicator_name) {
                        matches.push(m);
                    }
                }
            }
        }

        let total_score = matches.iter().map(|m| m.basescore).sum();
        let is_suspicious = !matches.is_empty();
        let sigma_matches = self.evaluate_decoded_with_sigma(decoded.as_deref());

        PsAnalysisResult {
            command_line: truncate_for_display(command_line, 500),
            matches,
            total_score,
            is_suspicious,
            decoded_content,
            sigma_matches,
        }
    }

    /// Run all indicators against a string (command line or decoded script); return matches.
    fn run_indicators(&self, text: &str, matched_against: Option<&str>) -> Vec<PsMatch> {
        let mut out = Vec::new();
        for ind in &self.indicators {
            if let Some(captured) = ind.regex.find(text) {
                let matched_substring = if captured.as_str().len() <= 200 {
                    Some(captured.as_str().to_string())
                } else {
                    Some(format!("{}...", &captured.as_str()[..197]))
                };
                out.push(PsMatch {
                    indicator_name: ind.name.clone(),
                    basescore: ind.basescore,
                    tactic: ind.tactic.clone(),
                    technique: ind.technique.clone(),
                    matched_substring,
                    matched_against: matched_against.map(String::from),
                });
            }
        }
        out
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn evaluate_decoded_with_sigma(&self, decoded: Option<&str>) -> Vec<SigmaMatchInfo> {
        let (engine, decoded) = match (self.sigma_engine.as_ref(), decoded) {
            (Some(eng), Some(d)) if !d.is_empty() => (eng, d),
            _ => return vec![],
        };
        let log = log_entry_from_decoded(decoded);
        engine
            .evaluate_log_entry(&log)
            .into_iter()
            .map(|m| SigmaMatchInfo {
                rule_id: m.rule_id.clone(),
                rule_title: m.rule_title.clone(),
                level: m.level.clone(),
            })
            .collect()
    }

    #[cfg(target_arch = "wasm32")]
    fn evaluate_decoded_with_sigma(&self, _decoded: Option<&str>) -> Vec<SigmaMatchInfo> {
        vec![]
    }

    /// Number of loaded psexposed indicators
    pub fn indicator_count(&self) -> usize {
        self.indicators.len()
    }

    /// Names of all loaded indicators (for display in UI).
    pub fn indicator_names(&self) -> Vec<String> {
        self.indicators.iter().map(|i| i.name.clone()).collect()
    }

    /// Full metadata for all loaded indicators (for display in UI).
    pub fn indicator_infos(&self) -> Vec<IndicatorInfo> {
        self.indicators
            .iter()
            .map(|i| IndicatorInfo {
                name: i.name.clone(),
                description: i.description.clone(),
                regex: i.regex_pattern.clone(),
                basescore: i.basescore,
                tactic: i.tactic.clone(),
                technique: i.technique.clone(),
                reference: i.reference.clone(),
            })
            .collect()
    }

    /// Whether Sigma rules are loaded (decoded content will be analyzed)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn has_sigma_rules(&self) -> bool {
        self.sigma_engine.is_some()
    }

    #[cfg(target_arch = "wasm32")]
    pub fn has_sigma_rules(&self) -> bool {
        false
    }
}

/// Build a log entry for Sigma: CommandLine = decoded script, ProcessName = powershell.exe
#[cfg(not(target_arch = "wasm32"))]
fn log_entry_from_decoded(decoded: &str) -> LogEntry {
    let mut fields = HashMap::new();
    fields.insert(
        "CommandLine".to_string(),
        serde_json::Value::String(decoded.to_string()),
    );
    fields.insert(
        "ProcessName".to_string(),
        serde_json::Value::String("powershell.exe".to_string()),
    );
    LogEntry { fields }
}

fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ps_indicator::PsIndicatorYaml;

    #[test]
    fn test_analyze_match() {
        let yaml = PsIndicatorYaml {
            name: "Invoke-Expression".to_string(),
            description: String::new(),
            regex: r"Invoke-Expression|\biex\b".to_string(),
            basescore: 5.0,
            tactic: "TA0002".to_string(),
            technique: vec!["T1059.001".to_string()],
            reference: vec![],
        };
        let compiled = yaml.compile().unwrap();
        let analyzer = PsAnalyzer {
            indicators: vec![compiled],
            #[cfg(not(target_arch = "wasm32"))]
            sigma_engine: None,
        };
        let result = analyzer.analyze("powershell -c iex (Get-Content x.ps1)");
        assert!(result.is_suspicious);
        assert_eq!(result.total_score, 5.0);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].indicator_name, "Invoke-Expression");
    }

    #[test]
    fn test_analyze_with_decoded_content() {
        let analyzer = PsAnalyzer {
            indicators: vec![],
            #[cfg(not(target_arch = "wasm32"))]
            sigma_engine: None,
        };
        let cmd = "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=";
        let result = analyzer.analyze(cmd);
        assert!(result.decoded_content.is_some());
        let dec = result.decoded_content.unwrap();
        assert!(dec.contains("echo"));
        assert!(dec.contains("Hello"));
    }
}
