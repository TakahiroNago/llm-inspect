//! Behavior of the optional `personal-ja` pack on top of the default rules.

use llm_inspect::{Category, Inspector, RuleSet};

fn inspector() -> Inspector {
    let mut set = RuleSet::default_rules();
    set.add_rules(RuleSet::pack("personal-ja").unwrap());
    Inspector::new(set).unwrap()
}

/// Rule ids of the personal-data findings in `text`, without duplicates.
fn pii_ids(text: &str) -> Vec<String> {
    let mut ids: Vec<String> = inspector()
        .scan(text)
        .findings
        .into_iter()
        .filter(|f| f.category == Category::Pii)
        .map(|f| f.rule_id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn found(text: &str, rule_id: &str) -> Vec<String> {
    inspector()
        .scan(text)
        .findings
        .iter()
        .filter(|f| f.rule_id == rule_id)
        .map(|f| f.excerpt(text).to_owned())
        .collect()
}

#[test]
fn the_pack_keeps_the_default_policy_and_compiles() {
    let i = inspector();
    assert_eq!(*i.policy(), RuleSet::default_rules().policy);
    assert!(i.rules().any(|r| r.id == "pii.ja.person_name"));
}

#[test]
fn names_with_an_honorific_or_a_title() {
    let rule = "pii.ja.person_name";
    assert_eq!(
        found("同僚の田中さんと上手くいきません", rule),
        ["田中さん"]
    );
    assert_eq!(found("山田社長に相談しました", rule), ["山田社長"]);
    assert_eq!(found("佐藤部長に確認してください", rule), ["佐藤部長"]);
    assert_eq!(found("鈴木課長が対応します", rule), ["鈴木課長"]);
    assert_eq!(found("高橋専務から連絡がありました", rule), ["高橋専務"]);
    assert_eq!(found("小笠原様、長谷川氏", rule), ["小笠原様", "長谷川氏"]);
}

#[test]
fn role_words_are_not_names() {
    let rule = "pii.ja.person_name";
    for text in [
        "上司さんやお客様、部長さんとの関係が不安です",
        "同僚さんに聞きました",
        "担当者様へ",
        "看護師さんが優しかった",
        "運転手さんにお礼を言った",
        "先生様",
    ] {
        assert_eq!(found(text, rule), Vec::<String>::new(), "{text}");
    }
}

#[test]
fn company_names() {
    let rule = "pii.ja.company";
    assert_eq!(
        found("株式会社サンプル商事で働いています", rule),
        ["株式会社サンプル商事"]
    );
    assert_eq!(
        found("山田商事株式会社に勤めています", rule),
        ["山田商事株式会社"]
    );
    assert_eq!(found("取引先はABC㈱です", rule).len(), 1);
    assert_eq!(found("会社に行きたくない", rule), Vec::<String>::new());
}

#[test]
fn street_addresses() {
    let rule = "pii.ja.address";
    assert_eq!(
        found("東京都渋谷区神南1丁目2番3号に住んでいます", rule),
        ["東京都渋谷区神南1丁目2番3号"]
    );
    assert_eq!(
        found("実家は横浜市中区本町3-12です", rule),
        ["横浜市中区本町3-12"]
    );
    assert_eq!(
        found("東京都に引っ越すべきか迷っています", rule),
        Vec::<String>::new()
    );
}

#[test]
fn postal_codes() {
    let rule = "pii.ja.postal_code";
    assert_eq!(found("〒150-0001 に住んでいます", rule), ["〒150-0001"]);
    assert_eq!(found("郵便番号は150-0001です", rule), ["150-0001"]);
    assert_eq!(found("〒1500001", rule), ["〒1500001"]);
    // Part of a phone number or a date is not a postal code.
    assert_eq!(found("090-1234-5678", rule), Vec::<String>::new());
    assert_eq!(found("2026-11-09", rule), Vec::<String>::new());
}

#[test]
fn phone_numbers_with_and_without_separators() {
    let rule = "pii.ja.phone";
    assert_eq!(
        found("090-1234-5678に電話が来ます", rule),
        ["090-1234-5678"]
    );
    assert_eq!(found("09012345678です", rule), ["09012345678"]);
    assert_eq!(found("03-1234-5678", rule), ["03-1234-5678"]);
    assert_eq!(found("0312345678", rule), ["0312345678"]);
    assert_eq!(found("0120 123 456", rule), ["0120 123 456"]);
    // Full-width digits and the dash-like characters people type for a hyphen.
    assert_eq!(found("０９０－１２３４－５６７８", rule).len(), 1);
    assert_eq!(found("090ー1234ー5678", rule).len(), 1);
    // Wrong number of digits, or not starting with 0.
    assert_eq!(found("03-1234-567", rule), Vec::<String>::new());
    assert_eq!(found("090-1234-56789", rule), Vec::<String>::new());
    assert_eq!(found("1234567890", rule), Vec::<String>::new());
}

#[test]
fn urls_and_handles() {
    assert_eq!(
        found("https://example.com/me を見て", "pii.ja.url"),
        ["https://example.com/me"]
    );
    assert_eq!(found("www.example.com です", "pii.ja.url").len(), 1);
    assert_eq!(
        found("インスタは @taro_yamada です", "pii.ja.sns_handle"),
        ["@taro_yamada"]
    );
    // The domain of an email address is not a handle.
    assert_eq!(
        found("taro@example.com", "pii.ja.sns_handle"),
        Vec::<String>::new()
    );
}

#[test]
fn ordinary_concerns_have_no_personal_data() {
    for text in [
        "35歳で年収500万円ですが転職すべきでしょうか",
        "2026年に新しい一歩を踏み出したい",
        "上司さんやお客様、部長さんとの関係が不安です",
        "東京都に引っ越すべきか迷っています",
        "人間関係に疲れてしまいました",
    ] {
        assert_eq!(pii_ids(text), Vec::<String>::new(), "{text}");
    }
}

#[test]
fn every_kind_in_one_text_is_found_and_redacted() {
    let text = "田中さんに090-1234-5678で連絡し、株式会社サンプル商事の東京都渋谷区神南1丁目2番3号へ行く。mail: a@example.com";
    assert_eq!(
        pii_ids(text),
        [
            "pii.email",
            "pii.ja.address",
            "pii.ja.company",
            "pii.ja.person_name",
            "pii.ja.phone",
            "pii.phone_jp",
        ]
    );

    let redacted = inspector().redact(text);
    assert_eq!(
        redacted.text,
        "[氏名]に[電話番号]で連絡し、[会社名]の[住所]へ行く。mail: [REDACTED:PII]"
    );
    // What is left has nothing more to find.
    assert_eq!(pii_ids(&redacted.text), Vec::<String>::new());
}

#[test]
fn two_names_separated_by_one_character_are_both_found() {
    assert_eq!(
        found("田中さん、鈴木さん", "pii.ja.person_name"),
        ["田中さん", "鈴木さん"]
    );
}
