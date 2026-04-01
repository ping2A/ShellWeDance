//! WASM bindings for ShellWeDance: analyze PowerShell command lines in the browser.
//! Indicators are loaded at runtime: fetch each file from indicators/ and call load_indicators_batch(json_array_of_yaml_strings).

use shell_we_dance_ps::ps_analyzer::{PsAnalyzer, PsAnalysisResult};
use wasm_bindgen::prelude::*;

/// Per-rule load error (index in the batch, message).
#[derive(serde::Serialize)]
struct LoadError {
    index: usize,
    message: String,
}

/// App state: analyzer built from indicators loaded via load_indicators_batch().
#[wasm_bindgen]
pub struct ShellWeDanceApp {
    analyzer: Option<PsAnalyzer>,
    /// Per-rule load errors from the last load_indicators_batch (index, message).
    load_errors: Vec<(usize, String)>,
}

#[wasm_bindgen]
impl ShellWeDanceApp {
    /// Create an empty app. Call load_indicators_batch(json_array_string) with a JSON array of YAML strings (one per fetched file).
    #[wasm_bindgen(constructor)]
    pub fn new() -> ShellWeDanceApp {
        ShellWeDanceApp {
            analyzer: None,
            load_errors: Vec::new(),
        }
    }

    /// Load indicators from multiple YAML strings (one per rule file). Pass a JSON string of an array of strings, e.g. `["yaml1...", "yaml2..."]`.
    /// Rules that fail to parse are skipped; call get_load_errors_json() after to see per-rule errors.
    #[wasm_bindgen]
    pub fn load_indicators_batch(&mut self, json_array_of_yaml_strings: String) -> Result<(), JsValue> {
        let contents: Vec<String> = serde_json::from_str(&json_array_of_yaml_strings)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let refs: Vec<&str> = contents.iter().map(String::as_str).collect();
        let (analyzer, errors) = PsAnalyzer::from_yaml_strings_with_errors(&refs);
        self.analyzer = Some(analyzer);
        self.load_errors = errors;
        Ok(())
    }

    /// JSON array of per-rule load errors from the last load_indicators_batch. Each item is { "index": number, "message": string }.
    /// Empty if all rules loaded successfully.
    #[wasm_bindgen]
    pub fn get_load_errors_json(&self) -> String {
        let arr: Vec<LoadError> = self
            .load_errors
            .iter()
            .map(|(index, message)| LoadError {
                index: *index,
                message: message.clone(),
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
    }

    /// Analyze a PowerShell command line. Returns JSON string of PsAnalysisResult.
    /// Fails if load_indicators() was not called yet.
    #[wasm_bindgen]
    pub fn analyze(&self, command: String) -> Result<String, JsValue> {
        let analyzer = self
            .analyzer
            .as_ref()
            .ok_or_else(|| JsValue::from_str("indicators not loaded; call load_indicators() first"))?;
        let result: PsAnalysisResult = analyzer.analyze(&command);
        Ok(serde_json::to_string(&result).unwrap_or_else(|_| "{}".into()))
    }

    /// Number of loaded indicators (0 if not loaded).
    #[wasm_bindgen]
    pub fn indicator_count(&self) -> usize {
        self.analyzer
            .as_ref()
            .map(|a| a.indicator_count())
            .unwrap_or(0)
    }

    /// JSON array of loaded indicator names (empty array if not loaded).
    #[wasm_bindgen]
    pub fn indicator_names_json(&self) -> String {
        match &self.analyzer {
            Some(a) => serde_json::to_string(&a.indicator_names()).unwrap_or_else(|_| "[]".into()),
            None => "[]".into(),
        }
    }

    /// JSON array of full indicator metadata (empty if not loaded).
    #[wasm_bindgen]
    pub fn indicator_infos_json(&self) -> String {
        match &self.analyzer {
            Some(a) => serde_json::to_string(&a.indicator_infos()).unwrap_or_else(|_| "[]".into()),
            None => "[]".into(),
        }
    }
}
