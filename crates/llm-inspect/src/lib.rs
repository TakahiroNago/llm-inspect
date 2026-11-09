//! Input and output security inspection for LLM applications.
//!
//! `llm-inspect` sits between your application and a large language model and
//! answers two questions:
//!
//! 1. **Is this input safe to send?** — [`Inspector::scan`] looks for personal
//!    data (PII), credentials (secrets) and prompt-injection patterns. Text is
//!    normalized first (NFKC, zero-width characters removed) so that full-width
//!    letters or hidden characters do not bypass the rules. [`Inspector::redact`]
//!    masks what it found.
//! 2. **Is this output safe to act on?** — [`OutputValidator::validate`] checks
//!    that a model response is JSON that matches a JSON Schema, that selected
//!    fields only contain allow-listed values, and that no HTML slipped in.
//!
//! Rules are plain regular expressions declared in TOML, so they can be audited
//! and extended without recompiling. The bundled rule set is a starting point,
//! not a guarantee: **pattern matching cannot detect every attack or every piece
//! of personal data.** Treat it as one layer in a defense-in-depth design, next
//! to human approval, least privilege and audit logging.
//!
//! # Example
//!
//! ```
//! use llm_inspect::{Decision, Inspector};
//!
//! let inspector = Inspector::with_default_rules();
//! let report = inspector.scan("My AWS key is AKIAIOSFODNN7EXAMPLE, please deploy.");
//! assert_eq!(report.decision, Decision::Block);
//! assert_eq!(report.findings[0].rule_id, "secret.aws_access_key");
//!
//! let redacted = inspector.redact("Contact me at taro@example.com");
//! assert_eq!(redacted.text, "Contact me at [REDACTED:PII]");
//! ```

#![forbid(unsafe_code)]

mod error;
mod input;
mod normalize;
mod output;
mod report;
mod rules;

pub use error::Error;
pub use input::Inspector;
pub use normalize::{Normalized, is_invisible};
pub use output::{
    AllowList, OutputPolicy, OutputReport, OutputValidator, Violation, ViolationKind,
    contains_html, strip_html,
};
pub use report::{Decision, Finding, Redacted, Report};
pub use rules::{Category, DEFAULT_RULES_TOML, Policy, Rule, RuleSet, Severity, Validator};
