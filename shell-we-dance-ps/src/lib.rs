//! PowerShell command-line analysis: psexposed-style indicators and `-EncodedCommand` decoding.
//! Intended for the WASM UI and as a dependency of the full `shell-we-dance` / Sigma stack.

pub mod ps_analyzer;
pub mod ps_decode;
pub mod ps_indicator;
