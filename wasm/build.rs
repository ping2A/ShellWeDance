// No embedded indicators: rules are loaded at runtime via fetch(/indicators/rules.yml).
// Generate rules.yml with: ./scripts/generate_rules_yml.sh (from repo root or wasm/)

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
