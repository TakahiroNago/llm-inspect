//! Rule definitions and the TOML format they are loaded from.
//!
//! A rule file looks like this:
//!
//! ```toml
//! [policy]
//! block_at = "high"      # findings at or above this severity block the input
//! warn_at = "medium"     # findings at or above this severity (below block_at) warn
//! redact = ["pii", "secret"]
//!
//! [[rules]]
//! id = "pii.email"
//! category = "pii"
//! severity = "medium"
//! description = "Email address"
//! pattern = '''[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'''
//! ```
//!
//! If a pattern contains a capture group, group 1 is reported as the finding;
//! otherwise the whole match is. This lets a rule anchor on context (for example
//! "not preceded by a digit") without the regex crate's lack of look-around.

use serde::{Deserialize, Serialize};

use crate::Error;

/// The bundled default rule set, as TOML.
pub const DEFAULT_RULES_TOML: &str = include_str!("../rules/default.toml");

/// What kind of problem a rule detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Category {
    /// Personally identifiable information (email, phone, card numbers...).
    Pii,
    /// Credentials and keys.
    Secret,
    /// Prompt-injection or jailbreak attempts, including obfuscation signals.
    Injection,
}

impl Category {
    /// Upper-case label used in default redaction markers.
    pub fn label(self) -> &'static str {
        match self {
            Category::Pii => "PII",
            Category::Secret => "SECRET",
            Category::Injection => "INJECTION",
        }
    }
}

/// How serious a finding is. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational; worth logging.
    Low,
    /// Likely sensitive; usually warn.
    Medium,
    /// Sensitive or dangerous; usually block.
    High,
    /// Credentials or clear attacks; block.
    Critical,
}

/// Extra validation applied to a regex match before it becomes a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Validator {
    /// The digits of the match must pass the Luhn checksum (payment cards).
    Luhn,
}

impl Validator {
    pub(crate) fn accepts(self, matched: &str) -> bool {
        match self {
            Validator::Luhn => luhn(matched),
        }
    }
}

/// Luhn checksum over the ASCII digits of `s`; non-digits are ignored.
/// Requires 13 to 19 digits, the range used by payment card numbers.
fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let dd = d * 2;
                if dd > 9 { dd - 9 } else { dd }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// A single detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable identifier, e.g. `pii.email`. Must be unique within a rule set.
    pub id: String,
    /// Category of the finding.
    pub category: Category,
    /// Severity of the finding.
    pub severity: Severity,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Regular expression (regex crate syntax). Group 1, if present, is the finding.
    pub pattern: String,
    /// Optional extra validation of the matched text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<Validator>,
    /// Replacement used by [`Inspector::redact`](crate::Inspector::redact).
    /// Defaults to `[REDACTED:<CATEGORY>]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redact_with: Option<String>,
}

/// Decision thresholds and redaction settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Findings at or above this severity make the decision [`Block`](crate::Decision::Block).
    pub block_at: Severity,
    /// Findings at or above this severity (and below `block_at`) make the decision
    /// [`Warn`](crate::Decision::Warn).
    pub warn_at: Severity,
    /// Categories that [`Inspector::redact`](crate::Inspector::redact) masks.
    pub redact: Vec<Category>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            block_at: Severity::High,
            warn_at: Severity::Medium,
            redact: vec![Category::Pii, Category::Secret],
        }
    }
}

/// A policy plus a list of rules; the unit that is loaded from TOML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleSet {
    /// Decision thresholds.
    pub policy: Policy,
    /// Detection rules.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// The bundled default rules.
    ///
    /// # Panics
    ///
    /// Never in practice: the bundled TOML is validated by the crate's tests.
    pub fn default_rules() -> Self {
        Self::from_toml(DEFAULT_RULES_TOML).expect("bundled rules must parse")
    }

    /// Parses a rule set from TOML. Patterns are compiled later by
    /// [`Inspector::new`](crate::Inspector::new).
    pub fn from_toml(toml_text: &str) -> Result<Self, Error> {
        Ok(toml::from_str(toml_text)?)
    }

    /// Appends the rules of `other` and takes its policy.
    pub fn merge(&mut self, other: RuleSet) {
        self.policy = other.policy;
        self.rules.extend(other.rules);
    }

    /// Checks that ids are non-empty and unique.
    pub(crate) fn validate_ids(&self) -> Result<(), Error> {
        let mut seen = std::collections::HashSet::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.id.is_empty() {
                return Err(Error::EmptyRuleId(i));
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(Error::DuplicateRuleId(rule.id.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_test_numbers() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(luhn("5555-5555-5555-4444"));
        assert!(luhn("378282246310005"));
    }

    #[test]
    fn luhn_rejects_bad_checksum_and_wrong_length() {
        assert!(!luhn("4111 1111 1111 1112"));
        assert!(!luhn("1234"));
        assert!(!luhn("12345678901234567890"));
    }

    #[test]
    fn default_rules_parse_and_have_unique_ids() {
        let rs = RuleSet::default_rules();
        assert!(rs.rules.len() >= 10);
        rs.validate_ids().unwrap();
    }

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let rs = RuleSet::from_toml(
            r#"
            [[rules]]
            id = "a"
            category = "pii"
            severity = "low"
            pattern = "x"
            [[rules]]
            id = "a"
            category = "pii"
            severity = "low"
            pattern = "y"
            "#,
        )
        .unwrap();
        assert!(matches!(rs.validate_ids(), Err(Error::DuplicateRuleId(id)) if id == "a"));
    }
}
