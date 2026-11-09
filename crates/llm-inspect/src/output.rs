//! Output validation: JSON Schema, allow-lists and HTML checks for model responses.
//!
//! The typical use is a model that is asked to return a JSON plan. Before the
//! plan is executed, the application checks that it is well-formed JSON, that
//! it matches the schema the model was given, that every `action` field is one
//! of the actions the application actually permits, and that no HTML is hiding
//! in string values that will later be rendered.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Error;

/// An allow-list applied to the values selected by a JSON pointer.
///
/// The pointer uses `/` separated segments like RFC 6901, with the addition
/// that `*` matches every element of an array (or every member of an object).
/// Example: `/steps/*/action`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowList {
    /// Pointer to the values to check, e.g. `/steps/*/action`.
    pub pointer: String,
    /// Permitted values. Non-string values are compared by their JSON text.
    pub values: Vec<String>,
}

/// What an output must satisfy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputPolicy {
    /// JSON Schema the output must match. When set, the output must be JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
    /// Allow-lists for selected fields. Requires the output to be JSON.
    pub allow: Vec<AllowList>,
    /// Reject HTML tags in the output (in string values if JSON, else in the raw text).
    pub forbid_html: bool,
    /// Maximum size of the output in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
}

/// Kind of an output violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ViolationKind {
    /// The output exceeds `max_bytes`.
    TooLong,
    /// The policy needs JSON but the output is not valid JSON.
    NotJson,
    /// The output does not match the JSON Schema.
    Schema,
    /// A value is not in its allow-list.
    NotAllowed,
    /// HTML was found.
    Html,
}

/// One problem found in an output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Kind of violation.
    pub kind: ViolationKind,
    /// JSON pointer to the offending value (empty for the whole document).
    pub path: String,
    /// Human-readable explanation. Never contains the offending value itself.
    pub message: String,
}

/// Result of [`OutputValidator::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputReport {
    /// Violations found; empty means the output is acceptable.
    pub violations: Vec<Violation>,
    /// The parsed JSON, when the output parsed as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<Value>,
}

impl OutputReport {
    /// `true` when there are no violations.
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Validates model outputs against an [`OutputPolicy`].
pub struct OutputValidator {
    policy: OutputPolicy,
    schema: Option<jsonschema::Validator>,
}

impl std::fmt::Debug for OutputValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputValidator")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl OutputValidator {
    /// Compiles the schema (if any) and checks the allow-list pointers.
    pub fn new(policy: OutputPolicy) -> Result<Self, Error> {
        for a in &policy.allow {
            if !a.pointer.starts_with('/') {
                return Err(Error::InvalidPointer(a.pointer.clone()));
            }
        }
        let schema = match &policy.schema {
            Some(s) => Some(
                jsonschema::validator_for(s).map_err(|e| Error::InvalidSchema(e.to_string()))?,
            ),
            None => None,
        };
        Ok(Self { policy, schema })
    }

    /// The policy in effect.
    pub fn policy(&self) -> &OutputPolicy {
        &self.policy
    }

    /// Validates `text`.
    pub fn validate(&self, text: &str) -> OutputReport {
        let mut violations = Vec::new();

        if let Some(max) = self.policy.max_bytes
            && text.len() > max
        {
            violations.push(Violation {
                kind: ViolationKind::TooLong,
                path: String::new(),
                message: format!("output is {} bytes, limit is {max}", text.len()),
            });
        }

        let needs_json = self.schema.is_some() || !self.policy.allow.is_empty();
        let json: Option<Value> = serde_json::from_str(text).ok();

        match &json {
            None if needs_json => violations.push(Violation {
                kind: ViolationKind::NotJson,
                path: String::new(),
                message: "output is not valid JSON".to_owned(),
            }),
            None => {
                if self.policy.forbid_html && contains_html(text) {
                    violations.push(Violation {
                        kind: ViolationKind::Html,
                        path: String::new(),
                        message: "output contains HTML".to_owned(),
                    });
                }
            }
            Some(v) => {
                if let Some(schema) = &self.schema {
                    for err in schema.iter_errors(v) {
                        violations.push(Violation {
                            kind: ViolationKind::Schema,
                            path: err.instance_path().to_string(),
                            message: schema_message(&err),
                        });
                    }
                }
                for a in &self.policy.allow {
                    let mut hits = Vec::new();
                    select(v, &a.pointer[1..], String::new(), &mut hits);
                    for (path, val) in hits {
                        let s = match val {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        if !a.values.contains(&s) {
                            violations.push(Violation {
                                kind: ViolationKind::NotAllowed,
                                path,
                                message: format!(
                                    "value is not in the allow-list for {}",
                                    a.pointer
                                ),
                            });
                        }
                    }
                }
                if self.policy.forbid_html {
                    let mut hits = Vec::new();
                    strings(v, String::new(), &mut hits);
                    for (path, s) in hits {
                        if contains_html(s) {
                            violations.push(Violation {
                                kind: ViolationKind::Html,
                                path,
                                message: "string value contains HTML".to_owned(),
                            });
                        }
                    }
                }
            }
        }

        OutputReport { violations, json }
    }
}

/// A schema error message without the offending instance value.
fn schema_message(err: &jsonschema::ValidationError<'_>) -> String {
    let keyword = err.kind();
    format!("schema violation at `{}`: {keyword:?}", err.schema_path())
}

/// Walks `pointer` (without its leading `/`) through `v`, expanding `*`.
fn select<'a>(v: &'a Value, pointer: &str, path: String, out: &mut Vec<(String, &'a Value)>) {
    if pointer.is_empty() {
        out.push((path, v));
        return;
    }
    let (head, rest) = pointer.split_once('/').unwrap_or((pointer, ""));
    let head = head.replace("~1", "/").replace("~0", "~");
    match v {
        Value::Array(items) if head == "*" => {
            for (i, item) in items.iter().enumerate() {
                select(item, rest, format!("{path}/{i}"), out);
            }
        }
        Value::Array(items) => {
            if let Ok(i) = head.parse::<usize>()
                && let Some(item) = items.get(i)
            {
                select(item, rest, format!("{path}/{i}"), out);
            }
        }
        Value::Object(map) if head == "*" => {
            for (k, item) in map {
                select(item, rest, format!("{path}/{}", escape(k)), out);
            }
        }
        Value::Object(map) => {
            if let Some(item) = map.get(&head) {
                select(item, rest, format!("{path}/{}", escape(&head)), out);
            }
        }
        _ => {}
    }
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// Collects every string value in `v` with its JSON pointer.
fn strings<'a>(v: &'a Value, path: String, out: &mut Vec<(String, &'a str)>) {
    match v {
        Value::String(s) => out.push((path, s)),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                strings(item, format!("{path}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (k, item) in map {
                strings(item, format!("{path}/{}", escape(k)), out);
            }
        }
        _ => {}
    }
}

fn html_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)</?[a-z][a-z0-9-]*(?:\s[^<>]*)?/?>|<!--|<!\[cdata\[")
            .expect("valid regex")
    })
}

/// Returns `true` if `text` contains something that looks like an HTML tag,
/// comment or CDATA section.
///
/// This is a detector, not a parser: it errs on the side of reporting.
pub fn contains_html(text: &str) -> bool {
    html_regex().is_match(text)
}

/// Removes HTML tags, comments and CDATA markers from `text`.
///
/// **This is not an HTML sanitizer.** It does not decode entities, handle
/// malformed markup the way browsers do, or protect against every XSS vector.
/// Use it to clean up plain-text display, and a real sanitizer for anything
/// rendered as HTML.
pub fn strip_html(text: &str) -> String {
    html_regex().replace_all(text, "").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_tags_comments_and_cdata() {
        assert!(contains_html("hi <b>there</b>"));
        assert!(contains_html("<SCRIPT src=x>"));
        assert!(contains_html("<!-- hidden -->"));
        assert!(contains_html("<![CDATA[x]]>"));
        assert!(!contains_html("a < b and c > d"));
        assert!(!contains_html("1 <2> 3")); // tag names start with a letter
    }

    #[test]
    fn strip_removes_tags_only() {
        assert_eq!(strip_html("<p>Hello <b>world</b></p>"), "Hello world");
    }

    #[test]
    fn pointer_wildcards_select_array_elements() {
        let v = json!({"steps": [{"action": "read"}, {"action": "delete"}]});
        let mut out = Vec::new();
        select(&v, "steps/*/action", String::new(), &mut out);
        let paths: Vec<_> = out.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["/steps/0/action", "/steps/1/action"]);
    }

    #[test]
    fn pointer_escapes_are_decoded() {
        let v = json!({"a/b": {"~": 1}});
        let mut out = Vec::new();
        select(&v, "a~1b/~0", String::new(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "/a~1b/~0");
    }

    #[test]
    fn rejects_bad_pointer() {
        let err = OutputValidator::new(OutputPolicy {
            allow: vec![AllowList {
                pointer: "steps".into(),
                values: vec![],
            }],
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(err, Error::InvalidPointer(_)));
    }
}
