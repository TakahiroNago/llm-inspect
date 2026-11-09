//! Fuzz target: scanning and redacting arbitrary text with the default rules.
//!
//! Checks that nothing panics, that every finding points at valid char
//! boundaries of the input, and that `redact` reports the same findings as `scan`.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use llm_inspect::Inspector;

static INSPECTOR: LazyLock<Inspector> = LazyLock::new(Inspector::with_default_rules);

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let report = INSPECTOR.scan(text);
    for f in &report.findings {
        assert!(f.start <= f.end && f.end <= text.len(), "bad span {f:?}");
        assert!(
            text.is_char_boundary(f.start) && text.is_char_boundary(f.end),
            "span not on char boundaries {f:?}"
        );
        let _ = f.excerpt(text);
    }
    assert!(report.findings.windows(2).all(|w| w[0].start <= w[1].start));
    let redacted = INSPECTOR.redact(text);
    assert_eq!(redacted.report, report);
    let _ = serde_json::to_string(&report).expect("report serializes");
});
