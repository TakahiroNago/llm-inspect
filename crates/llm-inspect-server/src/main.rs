//! `llm-inspect-server` binary: configuration, logging and graceful shutdown.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use llm_inspect::{Inspector, OutputPolicy, OutputValidator, RuleSet};
use llm_inspect_server::{AppState, Limits, VERSION, app};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "llm-inspect-server", version, about, long_about = None)]
struct Cli {
    /// Address to listen on. Defaults to loopback; put a reverse proxy in front for TLS.
    #[arg(long, env = "LLM_INSPECT_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// Additional rule file (TOML). Repeatable. Appended to the defaults unless --no-defaults.
    #[arg(long)]
    rules: Vec<PathBuf>,
    /// Use only the rules given with --rules.
    #[arg(long, requires = "rules")]
    no_defaults: bool,
    /// Named output policy as NAME=PATH (JSON file with an `OutputPolicy`). Repeatable.
    #[arg(long = "policy", value_name = "NAME=PATH")]
    policies: Vec<String>,
    /// Maximum request body size in bytes.
    #[arg(long, default_value_t = 1024 * 1024)]
    max_body_bytes: usize,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,
    /// Bearer token required on every route except /healthz. Prefer the env var.
    #[arg(long, env = "LLM_INSPECT_TOKEN", hide_env_values = true)]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info")),
        )
        .init();

    let cli = Cli::parse();

    let mut set = if cli.no_defaults {
        RuleSet::default()
    } else {
        RuleSet::default_rules()
    };
    for path in &cli.rules {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rules {}", path.display()))?;
        set.merge(RuleSet::from_toml(&text)?);
    }
    let inspector = Inspector::new(set)?;

    let mut policies = HashMap::new();
    for spec in &cli.policies {
        let Some((name, path)) = spec.split_once('=') else {
            bail!("--policy `{spec}` must look like NAME=PATH");
        };
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading policy {path}"))?;
        let policy: OutputPolicy =
            serde_json::from_str(&text).with_context(|| format!("parsing policy {path}"))?;
        let validator =
            OutputValidator::new(policy).with_context(|| format!("compiling policy `{name}`"))?;
        policies.insert(name.to_owned(), validator);
    }

    if cli.token.is_none() && !cli.bind.ip().is_loopback() {
        tracing::warn!(
            "listening on a non-loopback address without a bearer token; anyone who can reach {} can call the API",
            cli.bind
        );
    }

    let state = Arc::new(AppState::new(inspector, policies, cli.token));
    let limits = Limits {
        max_body_bytes: cli.max_body_bytes,
        timeout: Duration::from_secs(cli.timeout_secs),
    };
    let router = app(state, limits);

    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!(version = VERSION, addr = %cli.bind, "llm-inspect-server listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    tracing::info!("shut down");
    Ok(())
}

async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "failed to listen for ctrl-c");
    }
}
