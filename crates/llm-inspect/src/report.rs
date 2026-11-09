//! Results of an input scan.

use serde::{Deserialize, Serialize};

use crate::{Category, Severity};

/// What the caller should do with the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// No finding reached the warn threshold. Findings (if any) are informational.
    Allow,
    /// At least one finding reached the warn threshold but none reached the block threshold.
    Warn,
    /// At least one finding reached the block threshold.
    Block,
}

/// One match of one rule.
///
/// The matched text is deliberately **not** stored: reports are often logged,
/// and logging the very secret or personal data that was detected defeats the
/// purpose. Use [`Finding::excerpt`] when you really need it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Id of the rule that matched.
    pub rule_id: String,
    /// Category of the rule.
    pub category: Category,
    /// Severity of the rule.
    pub severity: Severity,
    /// Byte offset in the **original** text where the match starts.
    pub start: usize,
    /// Byte offset in the **original** text where the match ends (exclusive).
    pub end: usize,
    /// `true` if the rule matched only after normalization (for example the
    /// input used full-width letters or zero-width characters). This is a
    /// strong signal of deliberate evasion.
    pub normalized_only: bool,
}

impl Finding {
    /// The matched slice of `original`, which must be the text that was scanned.
    ///
    /// # Panics
    ///
    /// Panics if the offsets are out of range or not on char boundaries, i.e.
    /// if `original` is not the scanned text.
    pub fn excerpt<'a>(&self, original: &'a str) -> &'a str {
        &original[self.start..self.end]
    }
}

/// Result of [`Inspector::scan`](crate::Inspector::scan).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Overall decision according to the policy thresholds.
    pub decision: Decision,
    /// Findings sorted by start offset, then by descending severity.
    pub findings: Vec<Finding>,
    /// Whether normalization changed the text (full-width, compatibility or
    /// invisible characters were present).
    pub normalized: bool,
    /// Number of invisible characters that were removed during normalization.
    pub removed_invisible: usize,
}

impl Report {
    /// `true` if the decision is [`Decision::Block`].
    pub fn is_blocked(&self) -> bool {
        self.decision == Decision::Block
    }

    /// The highest severity among the findings, if any.
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Findings of one category.
    pub fn by_category(&self, category: Category) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.category == category)
    }
}

/// Result of [`Inspector::redact`](crate::Inspector::redact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redacted {
    /// The input with redactable findings replaced by markers.
    pub text: String,
    /// The scan report the redaction was based on (offsets refer to the original text).
    pub report: Report,
}
