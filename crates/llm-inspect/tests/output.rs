//! Output validation against a schema, allow-lists and HTML checks.

use llm_inspect::{AllowList, OutputPolicy, OutputValidator, ViolationKind};
use serde_json::json;

fn plan_validator() -> OutputValidator {
    OutputValidator::new(OutputPolicy {
        schema: Some(json!({
            "type": "object",
            "required": ["steps"],
            "additionalProperties": false,
            "properties": {
                "steps": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["action", "target"],
                        "properties": {
                            "action": {"type": "string"},
                            "target": {"type": "string", "maxLength": 200}
                        }
                    }
                }
            }
        })),
        allow: vec![AllowList {
            pointer: "/steps/*/action".into(),
            values: vec!["read".into(), "summarize".into(), "notify".into()],
        }],
        forbid_html: true,
        max_bytes: Some(4096),
    })
    .unwrap()
}

#[test]
fn valid_plan_passes() {
    let r = plan_validator().validate(
        r#"{"steps":[{"action":"read","target":"report.pdf"},{"action":"notify","target":"ops"}]}"#,
    );
    assert!(r.is_valid(), "{:?}", r.violations);
    assert!(r.json.is_some());
}

#[test]
fn non_json_is_rejected_when_schema_is_set() {
    let r = plan_validator().validate("Sure! Here is the plan: read the file.");
    assert_eq!(r.violations.len(), 1);
    assert_eq!(r.violations[0].kind, ViolationKind::NotJson);
}

#[test]
fn schema_violations_are_reported_with_paths() {
    let r = plan_validator().validate(r#"{"steps":[{"action":"read"}],"extra":1}"#);
    let kinds: Vec<_> = r.violations.iter().map(|v| v.kind).collect();
    assert!(kinds.iter().all(|k| *k == ViolationKind::Schema));
    assert!(r.violations.iter().any(|v| v.path == "/steps/0"));
}

#[test]
fn disallowed_action_is_rejected() {
    let r = plan_validator().validate(r#"{"steps":[{"action":"delete","target":"/"}]}"#);
    assert_eq!(r.violations.len(), 1);
    assert_eq!(r.violations[0].kind, ViolationKind::NotAllowed);
    assert_eq!(r.violations[0].path, "/steps/0/action");
    assert!(!r.violations[0].message.contains("delete"));
}

#[test]
fn html_in_string_values_is_rejected() {
    let r = plan_validator()
        .validate(r#"{"steps":[{"action":"notify","target":"<img src=x onerror=alert(1)>"}]}"#);
    assert_eq!(r.violations.len(), 1);
    assert_eq!(r.violations[0].kind, ViolationKind::Html);
    assert_eq!(r.violations[0].path, "/steps/0/target");
}

#[test]
fn html_in_plain_text_output() {
    let v = OutputValidator::new(OutputPolicy {
        forbid_html: true,
        ..Default::default()
    })
    .unwrap();
    assert!(v.validate("Plain answer with 2 < 3.").is_valid());
    assert_eq!(
        v.validate("<script>alert(1)</script>").violations[0].kind,
        ViolationKind::Html
    );
}

#[test]
fn max_bytes_is_enforced() {
    let v = OutputValidator::new(OutputPolicy {
        max_bytes: Some(5),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        v.validate("123456").violations[0].kind,
        ViolationKind::TooLong
    );
    assert!(v.validate("12345").is_valid());
}

#[test]
fn invalid_schema_is_an_error() {
    let err = OutputValidator::new(OutputPolicy {
        schema: Some(json!({"type": "not-a-type"})),
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("invalid JSON schema"));
}
