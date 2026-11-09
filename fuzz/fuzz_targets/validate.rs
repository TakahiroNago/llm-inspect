//! Fuzz target: validating arbitrary model output against a fixed policy.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use llm_inspect::{AllowList, OutputPolicy, OutputValidator, ViolationKind};
use serde_json::json;

static VALIDATOR: LazyLock<OutputValidator> = LazyLock::new(|| {
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
        max_bytes: Some(1 << 20),
    })
    .expect("fixed policy is valid")
});

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let report = VALIDATOR.validate(text);
    assert_eq!(report.is_valid(), report.violations.is_empty());
    if report.json.is_none() {
        assert!(report.violations.iter().any(|v| v.kind == ViolationKind::NotJson));
    }
    let _ = serde_json::to_string(&report).expect("report serializes");
});
