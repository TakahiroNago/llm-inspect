//! HTTP API for `llm-inspect`, built on axum.
//!
//! | Method | Path        | Body                                              | Response                     |
//! |--------|-------------|---------------------------------------------------|------------------------------|
//! | GET    | `/healthz`  | —                                                 | `{ "status": "ok", "version": "…" }` |
//! | GET    | `/rules`    | —                                                 | `{ "policy": …, "rules": […] }` |
//! | POST   | `/scan`     | `{ "text": "…" }`                                 | [`Report`] |
//! | POST   | `/redact`   | `{ "text": "…" }`                                 | [`Redacted`] |
//! | POST   | `/validate` | `{ "text": "…", "policy": {…} }` or `{ "text": "…", "policy_name": "…" }` | [`OutputReport`] |
//!
//! Errors are JSON objects `{ "error": "…" }` with `400` (bad request), `401`
//! (missing or wrong bearer token), `413` (body too large) or `415` (not JSON).
//!
//! Request bodies are never logged: they are exactly the text that may contain
//! secrets or personal data. Access logs record method, path, status and latency.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use llm_inspect::{Inspector, OutputPolicy, OutputReport, OutputValidator, Redacted, Report};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Crate version reported by `/healthz`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything a request handler needs. Build once, share behind an `Arc`.
pub struct AppState {
    inspector: Inspector,
    policies: HashMap<String, OutputValidator>,
    token: Option<String>,
}

impl AppState {
    /// Creates the state. `policies` are the named output policies selectable
    /// with `policy_name`; `token`, when set, is required as `Authorization: Bearer <token>`.
    pub fn new(
        inspector: Inspector,
        policies: HashMap<String, OutputValidator>,
        token: Option<String>,
    ) -> Self {
        Self {
            inspector,
            policies,
            token,
        }
    }
}

/// Server limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum request body size in bytes.
    pub max_body_bytes: usize,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Builds the router.
pub fn app(state: Arc<AppState>, limits: Limits) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/rules", get(rules))
        .route("/scan", post(scan))
        .route("/redact", post(redact))
        .route("/validate", post(validate))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_token,
        ))
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// JSON error body.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    /// Human-readable message. Never echoes the request body.
    pub error: String,
}

/// An error with an HTTP status.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        // `rejection.body_text()` describes the problem without quoting the body.
        Self::new(rejection.status(), rejection.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

/// Body of `/scan` and `/redact`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TextRequest {
    /// The text to inspect.
    pub text: String,
}

/// Body of `/validate`. Exactly one of `policy` and `policy_name` must be set.
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateRequest {
    /// The model output to validate.
    pub text: String,
    /// An inline output policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<OutputPolicy>,
    /// The name of a policy loaded at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
}

/// Response of `/healthz`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Health {
    /// Always `"ok"`.
    pub status: String,
    /// Server version.
    pub version: String,
}

/// Response of `/rules`.
#[derive(Debug, Serialize)]
pub struct RulesResponse<'a> {
    /// Decision thresholds in effect.
    pub policy: &'a llm_inspect::Policy,
    /// Rules in effect.
    pub rules: Vec<&'a llm_inspect::Rule>,
    /// Names of the output policies loaded at startup.
    pub output_policies: Vec<&'a str>,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok".to_owned(),
        version: VERSION.to_owned(),
    })
}

async fn rules(State(state): State<Arc<AppState>>) -> Response {
    let mut names: Vec<&str> = state.policies.keys().map(String::as_str).collect();
    names.sort_unstable();
    Json(RulesResponse {
        policy: state.inspector.policy(),
        rules: state.inspector.rules().collect(),
        output_policies: names,
    })
    .into_response()
}

async fn scan(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<TextRequest>, JsonRejection>,
) -> Result<Json<Report>, ApiError> {
    let Json(req) = payload?;
    Ok(Json(state.inspector.scan(&req.text)))
}

async fn redact(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<TextRequest>, JsonRejection>,
) -> Result<Json<Redacted>, ApiError> {
    let Json(req) = payload?;
    Ok(Json(state.inspector.redact(&req.text)))
}

async fn validate(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<ValidateRequest>, JsonRejection>,
) -> Result<Json<OutputReport>, ApiError> {
    let Json(req) = payload?;
    match (req.policy, req.policy_name) {
        (Some(_), Some(_)) => Err(ApiError::bad_request(
            "set either `policy` or `policy_name`, not both",
        )),
        (None, None) => Err(ApiError::bad_request(
            "one of `policy` or `policy_name` is required",
        )),
        (Some(policy), None) => {
            let validator = OutputValidator::new(policy)
                .map_err(|e| ApiError::bad_request(format!("invalid policy: {e}")))?;
            Ok(Json(validator.validate(&req.text)))
        }
        (None, Some(name)) => {
            let validator = state
                .policies
                .get(&name)
                .ok_or_else(|| ApiError::bad_request(format!("unknown policy_name `{name}`")))?;
            Ok(Json(validator.validate(&req.text)))
        }
    }
}

/// Requires `Authorization: Bearer <token>` on every route except `/healthz`
/// when a token is configured. Comparison is constant-time.
async fn require_token(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let Some(expected) = state.token.as_deref() else {
        return next.run(req).await;
    };
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let ok = presented.is_some_and(|p| {
        p.len() == expected.len() && bool::from(p.as_bytes().ct_eq(expected.as_bytes()))
    });
    if ok {
        next.run(req).await
    } else {
        ApiError::new(StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
    }
}
