//! Input inspection: scanning and redaction.

use std::collections::HashSet;

use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

use crate::Error;
use crate::normalize::Normalized;
use crate::report::{Decision, Finding, Redacted, Report};
use crate::rules::{Category, Policy, Rule, RuleSet, Severity};

/// Id of the built-in finding emitted when invisible characters were removed.
pub(crate) const INVISIBLE_RULE_ID: &str = "obfuscation.invisible_chars";

/// Upper bound on compiled regex size, to keep rule files from exhausting memory.
const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);

struct Compiled {
    rule: Rule,
    re: Regex,
    exclude: Option<Regex>,
}

/// Scans input text against a [`RuleSet`].
///
/// Building an inspector compiles every pattern, so build once and reuse it.
/// `Inspector` is `Send + Sync`.
pub struct Inspector {
    rules: Vec<Compiled>,
    set: RegexSet,
    policy: Policy,
}

impl std::fmt::Debug for Inspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inspector")
            .field("rules", &self.rules.len())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl Inspector {
    /// Compiles `rule_set`.
    pub fn new(rule_set: RuleSet) -> Result<Self, Error> {
        rule_set.validate_ids()?;
        let mut rules = Vec::with_capacity(rule_set.rules.len());
        for rule in rule_set.rules {
            let compile = |pattern: &str| {
                RegexBuilder::new(pattern)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|e| Error::InvalidPattern {
                        id: rule.id.clone(),
                        source: Box::new(e),
                    })
            };
            let re = compile(&rule.pattern)?;
            let exclude = rule.exclude.as_deref().map(compile).transpose()?;
            rules.push(Compiled { rule, re, exclude });
        }
        let set = RegexSetBuilder::new(rules.iter().map(|c| c.rule.pattern.as_str()))
            .size_limit(REGEX_SIZE_LIMIT * 4)
            .build()
            .map_err(|e| Error::InvalidPattern {
                id: "<rule set>".to_owned(),
                source: Box::new(e),
            })?;
        Ok(Self {
            rules,
            set,
            policy: rule_set.policy,
        })
    }

    /// An inspector with the bundled default rules.
    ///
    /// # Panics
    ///
    /// Never in practice: the bundled rules are compiled in the crate's tests.
    pub fn with_default_rules() -> Self {
        Self::new(RuleSet::default_rules()).expect("bundled rules must compile")
    }

    /// The policy in effect.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The rules in effect, in order.
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(|c| &c.rule)
    }

    /// Scans `text` and returns every finding plus an overall decision.
    pub fn scan(&self, text: &str) -> Report {
        let norm = Normalized::new(text);
        let mut findings = Vec::new();

        for idx in self.set.matches(norm.text()) {
            let compiled = &self.rules[idx];
            // Spans the rule also produces on the raw text; used to tell
            // "matched only thanks to normalization" apart from plain matches.
            let raw_spans: Option<HashSet<(usize, usize)>> =
                norm.changed().then(|| spans(compiled, text).collect());

            for (s, e) in spans(compiled, norm.text()) {
                let (start, end) = norm.to_original(s, e);
                let normalized_only = raw_spans
                    .as_ref()
                    .is_some_and(|raw| !raw.contains(&(start, end)));
                findings.push(Finding {
                    rule_id: compiled.rule.id.clone(),
                    category: compiled.rule.category,
                    severity: compiled.rule.severity,
                    start,
                    end,
                    normalized_only,
                });
            }
        }

        if norm.removed_invisible() > 0 {
            findings.push(Finding {
                rule_id: INVISIBLE_RULE_ID.to_owned(),
                category: Category::Injection,
                severity: Severity::Low,
                start: 0,
                end: text.len(),
                normalized_only: true,
            });
        }

        findings.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| b.severity.cmp(&a.severity))
                .then_with(|| a.end.cmp(&b.end))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        let decision = decide(&self.policy, findings.iter().map(|f| f.severity).max());
        Report {
            decision,
            findings,
            normalized: norm.changed(),
            removed_invisible: norm.removed_invisible(),
        }
    }

    /// Scans `text` and replaces every finding whose category is listed in
    /// [`Policy::redact`] with a marker.
    ///
    /// Overlapping findings are merged; the marker of the first (highest
    /// severity) finding wins. Injection findings are not redacted by default
    /// because masking an instruction does not make it safe to forward.
    pub fn redact(&self, text: &str) -> Redacted {
        let report = self.scan(text);
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let mut pending: Option<(usize, usize, String)> = None;

        let redactable = report
            .findings
            .iter()
            .filter(|f| f.rule_id != INVISIBLE_RULE_ID && self.policy.redact.contains(&f.category));

        for f in redactable {
            let marker = self.marker_for(&f.rule_id, f.category);
            match pending.as_mut() {
                Some((_, end, _)) if f.start < *end => {
                    *end = (*end).max(f.end);
                }
                _ => {
                    if let Some((s, e, m)) = pending.take() {
                        out.push_str(&text[cursor..s]);
                        out.push_str(&m);
                        cursor = e;
                    }
                    pending = Some((f.start, f.end, marker));
                }
            }
        }
        if let Some((s, e, m)) = pending.take() {
            out.push_str(&text[cursor..s]);
            out.push_str(&m);
            cursor = e;
        }
        out.push_str(&text[cursor..]);

        Redacted { text: out, report }
    }

    fn marker_for(&self, rule_id: &str, category: Category) -> String {
        self.rules
            .iter()
            .find(|c| c.rule.id == rule_id)
            .and_then(|c| c.rule.redact_with.clone())
            .unwrap_or_else(|| format!("[REDACTED:{}]", category.label()))
    }
}

/// Byte spans of matches in `hay` (group 1 if the pattern has one), filtered by
/// the rule's validator and `exclude` pattern. Empty spans are skipped.
///
/// The search resumes right after the reported text, not after the whole
/// match. A rule such as `(?:^|[^0-9])(NUMBER)(?:[^0-9]|$)` consumes the
/// character after the number as context; resuming after the whole match would
/// leave the next number without the context it needs before it, so of two
/// numbers separated by a single character only the first would be found.
fn spans<'h>(compiled: &'h Compiled, hay: &'h str) -> impl Iterator<Item = (usize, usize)> + 'h {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        while pos <= hay.len() {
            let caps = compiled.re.captures_at(hay, pos)?;
            let whole = caps.get(0)?;
            let m = caps.get(1).unwrap_or(whole);

            pos = if !m.is_empty() {
                m.end()
            } else if whole.end() > pos {
                whole.end()
            } else {
                // An empty match at `pos`: step over one character.
                hay[pos..]
                    .chars()
                    .next()
                    .map_or(hay.len() + 1, |c| pos + c.len_utf8())
            };

            if m.is_empty() {
                continue;
            }
            if compiled
                .rule
                .validator
                .is_some_and(|v| !v.accepts(m.as_str()))
            {
                continue;
            }
            if compiled
                .exclude
                .as_ref()
                .is_some_and(|re| re.is_match(m.as_str()))
            {
                continue;
            }
            return Some((m.start(), m.end()));
        }
        None
    })
}

fn decide(policy: &Policy, highest: Option<Severity>) -> Decision {
    match highest {
        Some(s) if s >= policy.block_at => Decision::Block,
        Some(s) if s >= policy.warn_at => Decision::Warn,
        _ => Decision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspector(toml_text: &str) -> Inspector {
        Inspector::new(RuleSet::from_toml(toml_text).unwrap()).unwrap()
    }

    #[test]
    fn no_rules_allows_everything() {
        let i = inspector("");
        let r = i.scan("anything at all");
        assert_eq!(r.decision, Decision::Allow);
        assert_eq!(r.findings, Vec::new());
    }

    #[test]
    fn capture_group_one_is_the_finding() {
        let i = inspector(
            r#"
            [[rules]]
            id = "t"
            category = "pii"
            severity = "high"
            pattern = '''(?:^|[^0-9])(0[0-9]{2}-[0-9]{4}-[0-9]{4})(?:[^0-9]|$)'''
            "#,
        );
        let text = "tel: 090-1234-5678.";
        let r = i.scan(text);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].excerpt(text), "090-1234-5678");
        assert_eq!(r.decision, Decision::Block);
    }

    #[test]
    fn matches_that_share_a_context_character_are_all_found() {
        let i = inspector(
            r#"
            [[rules]]
            id = "t"
            category = "pii"
            severity = "medium"
            pattern = '''(?:^|[^0-9])(0[0-9]{2}-[0-9]{4}-[0-9]{4})(?:[^0-9]|$)'''
            "#,
        );
        let text = "090-1111-2222,080-3333-4444 070-5555-6666";
        let r = i.scan(text);
        let found: Vec<&str> = r.findings.iter().map(|f| f.excerpt(text)).collect();
        assert_eq!(found, ["090-1111-2222", "080-3333-4444", "070-5555-6666"]);
        assert_eq!(
            i.redact(text).text,
            "[REDACTED:PII],[REDACTED:PII] [REDACTED:PII]"
        );
    }

    #[test]
    fn a_pattern_that_can_match_nothing_does_not_loop() {
        let i = inspector(
            r#"
            [[rules]]
            id = "t"
            category = "pii"
            severity = "low"
            pattern = '''x*'''
            "#,
        );
        let text = "aあxxb";
        let r = i.scan(text);
        let found: Vec<&str> = r.findings.iter().map(|f| f.excerpt(text)).collect();
        assert_eq!(found, ["xx"]);
    }

    #[test]
    fn exclude_drops_matches_by_their_reported_text() {
        let i = inspector(
            r#"
            [[rules]]
            id = "t"
            category = "pii"
            severity = "medium"
            pattern = '''(?:^|[^a-z])([a-z]+)@'''
            exclude = '''^(?:info|support)$'''
            "#,
        );
        let text = "info@ taro@ support@ infodesk@";
        let r = i.scan(text);
        let found: Vec<&str> = r.findings.iter().map(|f| f.excerpt(text)).collect();
        assert_eq!(found, ["taro", "infodesk"]);
    }

    #[test]
    fn invalid_exclude_names_the_rule() {
        let err = Inspector::new(
            RuleSet::from_toml(
                r#"
                [[rules]]
                id = "broken-exclude"
                category = "pii"
                severity = "low"
                pattern = "x"
                exclude = "("
                "#,
            )
            .unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidPattern { id, .. } if id == "broken-exclude"));
    }

    #[test]
    fn thresholds_drive_the_decision() {
        let i = inspector(
            r#"
            [policy]
            block_at = "critical"
            warn_at = "high"
            [[rules]]
            id = "t"
            category = "injection"
            severity = "high"
            pattern = "ignore"
            "#,
        );
        assert_eq!(i.scan("please ignore").decision, Decision::Warn);
        assert_eq!(i.scan("fine").decision, Decision::Allow);
    }

    #[test]
    fn redaction_merges_overlaps_and_respects_categories() {
        let i = inspector(
            r#"
            [[rules]]
            id = "a"
            category = "pii"
            severity = "high"
            pattern = "abcd"
            [[rules]]
            id = "b"
            category = "pii"
            severity = "low"
            pattern = "cdef"
            redact_with = "<b>"
            [[rules]]
            id = "c"
            category = "injection"
            severity = "high"
            pattern = "xyz"
            "#,
        );
        let r = i.redact("..abcdef..xyz");
        assert_eq!(r.text, "..[REDACTED:PII]..xyz");
        assert_eq!(r.report.findings.len(), 3);
    }

    #[test]
    fn invalid_pattern_names_the_rule() {
        let err = Inspector::new(
            RuleSet::from_toml(
                r#"
                [[rules]]
                id = "broken"
                category = "pii"
                severity = "low"
                pattern = "("
                "#,
            )
            .unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidPattern { id, .. } if id == "broken"));
    }
}
