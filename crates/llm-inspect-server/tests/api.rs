//! End-to-end tests of the HTTP API without opening a socket (tower `oneshot`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use llm_inspect::{AllowList, Inspector, OutputPolicy, OutputValidator};
use llm_inspect_server::{AppState, ErrorBody, Health, Limits, app};
use serde_json::{Value, json};
use tower::ServiceExt;

fn plan_policy() -> OutputPolicy {
    OutputPolicy {
        schema: Some(json!({
            "type": "object",
            "required": ["steps"],
            "properties": {"steps": {"type": "array", "items": {
                "type": "object", "required": ["action", "target"],
                "properties": {"action": {"type": "string"}, "target": {"type": "string"}}
            }}}
        })),
        allow: vec![AllowList {
            pointer: "/steps/*/action".into(),
            values: vec!["read".into(), "notify".into()],
        }],
        forbid_html: true,
        max_bytes: Some(4096),
    }
}

fn router(token: Option<&str>, limits: Limits) -> Router {
    let mut policies = HashMap::new();
    policies.insert(
        "plan".to_owned(),
        OutputValidator::new(plan_policy()).unwrap(),
    );
    let state = Arc::new(AppState::new(
        Inspector::with_default_rules(),
        policies,
        token.map(str::to_owned),
    ));
    app(state, limits)
}

async fn call(router: Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, json)
}

fn post_json(path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn healthz_reports_version() {
    let (status, body) = call(
        router(None, Limits::default()),
        Request::get("/healthz").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let health: Health = serde_json::from_value(body).unwrap();
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn rules_lists_defaults_and_policy_names() {
    let (status, body) = call(
        router(None, Limits::default()),
        Request::get("/rules").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["rules"].as_array().unwrap().len() >= 10);
    assert_eq!(body["policy"]["block_at"], "high");
    assert_eq!(body["output_policies"], json!(["plan"]));
}

#[tokio::test]
async fn scan_blocks_a_secret_without_echoing_it() {
    let (status, body) = call(
        router(None, Limits::default()),
        post_json("/scan", &json!({"text": "key AKIAIOSFODNN7EXAMPLE"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "block");
    assert_eq!(body["findings"][0]["rule_id"], "secret.aws_access_key");
    assert!(!body.to_string().contains("AKIAIOSFODNN7EXAMPLE"));
}

#[tokio::test]
async fn redact_masks_pii() {
    let (status, body) = call(
        router(None, Limits::default()),
        post_json("/redact", &json!({"text": "mail taro@example.com now"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["text"], "mail [REDACTED:PII] now");
    assert_eq!(body["report"]["decision"], "warn");
}

#[tokio::test]
async fn validate_with_inline_policy() {
    let (status, body) = call(
        router(None, Limits::default()),
        post_json(
            "/validate",
            &json!({
                "text": r#"{"steps":[{"action":"delete","target":"/"}]}"#,
                "policy": plan_policy(),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["violations"][0]["kind"], "not_allowed");
    assert_eq!(body["violations"][0]["path"], "/steps/0/action");
}

#[tokio::test]
async fn validate_with_named_policy_and_unknown_name() {
    let ok = call(
        router(None, Limits::default()),
        post_json(
            "/validate",
            &json!({"text": r#"{"steps":[{"action":"read","target":"a"}]}"#, "policy_name": "plan"}),
        ),
    )
    .await;
    assert_eq!(ok.0, StatusCode::OK);
    assert_eq!(ok.1["violations"], json!([]));

    let unknown = call(
        router(None, Limits::default()),
        post_json("/validate", &json!({"text": "{}", "policy_name": "nope"})),
    )
    .await;
    assert_eq!(unknown.0, StatusCode::BAD_REQUEST);
    let err: ErrorBody = serde_json::from_value(unknown.1).unwrap();
    assert!(err.error.contains("unknown policy_name"));
}

#[tokio::test]
async fn validate_requires_exactly_one_policy_source() {
    let none = call(
        router(None, Limits::default()),
        post_json("/validate", &json!({"text": "{}"})),
    )
    .await;
    assert_eq!(none.0, StatusCode::BAD_REQUEST);
    let both = call(
        router(None, Limits::default()),
        post_json(
            "/validate",
            &json!({"text": "{}", "policy": plan_policy(), "policy_name": "plan"}),
        ),
    )
    .await;
    assert_eq!(both.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_json_is_a_400_with_error_body() {
    let req = Request::builder()
        .method("POST")
        .uri("/scan")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{\"text\": "))
        .unwrap();
    let (status, body) = call(router(None, Limits::default()), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn wrong_content_type_is_415() {
    let req = Request::builder()
        .method("POST")
        .uri("/scan")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("hello"))
        .unwrap();
    let (status, _) = call(router(None, Limits::default()), req).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn oversized_body_is_413() {
    let limits = Limits {
        max_body_bytes: 64,
        timeout: Duration::from_secs(5),
    };
    let big = "a".repeat(200);
    let (status, body) = call(
        router(None, limits),
        post_json("/scan", &json!({"text": big})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn bearer_token_is_enforced_except_on_healthz() {
    let r = || router(Some("s3cret-token"), Limits::default());
    let (status, _) = call(r(), post_json("/scan", &json!({"text": "x"}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut req = post_json("/scan", &json!({"text": "x"}));
    req.headers_mut()
        .insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());
    let (status, _) = call(r(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut req = post_json("/scan", &json!({"text": "x"}));
    req.headers_mut().insert(
        header::AUTHORIZATION,
        "Bearer s3cret-token".parse().unwrap(),
    );
    let (status, body) = call(r(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "allow");

    let (status, _) = call(r(), Request::get("/healthz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}
