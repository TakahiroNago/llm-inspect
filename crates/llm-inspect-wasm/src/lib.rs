//! WebAssembly bindings for `llm-inspect`.
//!
//! The API exchanges JSON strings rather than JS objects so that the crate has
//! no dependency beyond `wasm-bindgen`. Build with
//! `wasm-pack build crates/llm-inspect-wasm --target web`.

use wasm_bindgen::prelude::*;

/// Installs a panic hook that forwards Rust panics to `console.error`.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// The bundled default rule set as TOML, for display or as an editing base.
#[wasm_bindgen]
pub fn default_rules_toml() -> String {
    llm_inspect::DEFAULT_RULES_TOML.to_owned()
}

/// Library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Input inspector. Build once, call `scan` / `redact` many times.
#[wasm_bindgen]
pub struct Inspector {
    inner: llm_inspect::Inspector,
}

#[wasm_bindgen]
impl Inspector {
    /// Creates an inspector. With `rules_toml` empty or omitted, the bundled
    /// default rules are used; otherwise the given TOML replaces them.
    ///
    /// # Errors
    ///
    /// Returns the parse or regex error message when the rules are invalid.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::needless_pass_by_value)] // wasm-bindgen needs an owned Option<String>
    pub fn new(rules_toml: Option<String>) -> Result<Inspector, JsError> {
        let set = match rules_toml.as_deref().map(str::trim) {
            Some(t) if !t.is_empty() => llm_inspect::RuleSet::from_toml(t)?,
            _ => llm_inspect::RuleSet::default_rules(),
        };
        Ok(Self {
            inner: llm_inspect::Inspector::new(set)?,
        })
    }

    /// Scans `text`; returns a JSON `Report`.
    pub fn scan(&self, text: &str) -> String {
        to_json(&self.inner.scan(text))
    }

    /// Scans and redacts `text`; returns a JSON `Redacted` (`{ text, report }`).
    pub fn redact(&self, text: &str) -> String {
        to_json(&self.inner.redact(text))
    }

    /// The rules in effect as a JSON array.
    pub fn rules(&self) -> String {
        to_json(&self.inner.rules().collect::<Vec<_>>())
    }
}

/// Validates a model output. `policy_json` is a JSON `OutputPolicy`
/// (`{ schema?, allow?: [{pointer, values}], forbid_html?, max_bytes? }`).
/// Returns a JSON `OutputReport`.
///
/// # Errors
///
/// Returns an error message when the policy or schema is invalid.
#[wasm_bindgen]
pub fn validate_output(text: &str, policy_json: &str) -> Result<String, JsError> {
    let policy: llm_inspect::OutputPolicy = serde_json::from_str(policy_json)?;
    let validator = llm_inspect::OutputValidator::new(policy)?;
    Ok(to_json(&validator.validate(text)))
}

fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| format!("{{\"error\":{:?}}}", e.to_string()))
}
