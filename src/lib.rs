// Library module to expose code for integration tests

#[cfg(not(target_arch = "wasm32"))]
pub mod engine;
pub mod models;
pub mod parser;
pub mod correlation;
pub mod correlation_parser;
pub mod ps_indicator;
pub mod ps_analyzer;
pub mod ps_decode;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod engine_tests;
mod models_tests;
mod parser_tests;
