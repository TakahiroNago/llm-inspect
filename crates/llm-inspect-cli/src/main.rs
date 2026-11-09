//! `llm-inspect` command-line tool.
//!
//! Exit codes: `0` allow / valid, `10` warn, `20` block / invalid, `1` usage or I/O error.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use llm_inspect::{
    AllowList, Decision, Inspector, OutputPolicy, OutputReport, OutputValidator, Report, RuleSet,
};

#[derive(Parser)]
#[command(name = "llm-inspect", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan input text for PII, secrets and prompt-injection patterns.
    Scan(ScanArgs),
    /// Validate model output against a JSON Schema, allow-lists and HTML checks.
    Validate(ValidateArgs),
    /// List the rules in effect.
    Rules(RulesArgs),
}

#[derive(Args)]
struct RuleSource {
    /// Additional rule file (TOML). Its rules are appended to the defaults
    /// and its policy replaces the default policy.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Use only the rules in --rules, not the bundled defaults.
    #[arg(long, requires = "rules")]
    no_defaults: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// File to read; stdin when omitted or `-`.
    input: Option<PathBuf>,
    #[command(flatten)]
    source: RuleSource,
    /// Print the redacted text instead of the report.
    #[arg(long)]
    redact: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Args)]
struct ValidateArgs {
    /// File to read; stdin when omitted or `-`.
    input: Option<PathBuf>,
    /// JSON Schema file the output must match.
    #[arg(long)]
    schema: Option<PathBuf>,
    /// Allow-list as `POINTER=v1,v2,...`, e.g. `/steps/*/action=read,notify`. Repeatable.
    #[arg(long = "allow", value_name = "POINTER=VALUES")]
    allow: Vec<String>,
    /// Reject HTML in the output.
    #[arg(long)]
    forbid_html: bool,
    /// Maximum output size in bytes.
    #[arg(long)]
    max_bytes: Option<usize>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Args)]
struct RulesArgs {
    #[command(flatten)]
    source: RuleSource,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

const EXIT_WARN: u8 = 10;
const EXIT_BLOCK: u8 = 20;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Scan(args) => scan(&args),
        Command::Validate(args) => validate(&args),
        Command::Rules(args) => rules(&args),
    }
}

fn scan(args: &ScanArgs) -> Result<ExitCode> {
    let inspector = args.source.build()?;
    let text = read_input(args.input.as_deref())?;
    let mut out = std::io::stdout().lock();
    if args.redact {
        let r = inspector.redact(&text);
        match args.format {
            Format::Text => writeln!(out, "{}", r.text)?,
            Format::Json => {
                serde_json::to_writer_pretty(&mut out, &r)?;
                writeln!(out)?;
            }
        }
        return Ok(exit_for(r.report.decision));
    }
    let report = inspector.scan(&text);
    match args.format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
        }
        Format::Text => print_report(&mut out, &report)?,
    }
    Ok(exit_for(report.decision))
}

fn print_report(out: &mut impl Write, report: &Report) -> Result<()> {
    writeln!(out, "decision: {:?}", report.decision)?;
    if report.normalized {
        writeln!(
            out,
            "normalized: yes ({} invisible characters removed)",
            report.removed_invisible
        )?;
    }
    for f in &report.findings {
        writeln!(
            out,
            "{:<9} {:<10} {:<40} bytes {}..{}{}",
            format!("{:?}", f.severity).to_lowercase(),
            format!("{:?}", f.category).to_lowercase(),
            f.rule_id,
            f.start,
            f.end,
            if f.normalized_only {
                "  (after normalization)"
            } else {
                ""
            }
        )?;
    }
    Ok(())
}

fn validate(args: &ValidateArgs) -> Result<ExitCode> {
    let schema = match &args.schema {
        Some(p) => {
            let s = std::fs::read_to_string(p)
                .with_context(|| format!("reading schema {}", p.display()))?;
            Some(serde_json::from_str(&s).context("parsing schema as JSON")?)
        }
        None => None,
    };
    let allow = args
        .allow
        .iter()
        .map(|s| parse_allow(s))
        .collect::<Result<Vec<_>>>()?;
    let validator = OutputValidator::new(OutputPolicy {
        schema,
        allow,
        forbid_html: args.forbid_html,
        max_bytes: args.max_bytes,
    })?;
    let text = read_input(args.input.as_deref())?;
    let report = validator.validate(&text);
    let mut out = std::io::stdout().lock();
    match args.format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
        }
        Format::Text => print_output_report(&mut out, &report)?,
    }
    Ok(if report.is_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_BLOCK)
    })
}

fn print_output_report(out: &mut impl Write, report: &OutputReport) -> Result<()> {
    if report.is_valid() {
        writeln!(out, "valid")?;
        return Ok(());
    }
    writeln!(out, "invalid: {} violation(s)", report.violations.len())?;
    for v in &report.violations {
        let path = if v.path.is_empty() {
            "<document>"
        } else {
            &v.path
        };
        writeln!(
            out,
            "{:<12} {:<30} {}",
            format!("{:?}", v.kind),
            path,
            v.message
        )?;
    }
    Ok(())
}

fn rules(args: &RulesArgs) -> Result<ExitCode> {
    let inspector = args.source.build()?;
    let mut out = std::io::stdout().lock();
    match args.format {
        Format::Json => {
            let rules: Vec<_> = inspector.rules().collect();
            serde_json::to_writer_pretty(&mut out, &rules)?;
            writeln!(out)?;
        }
        Format::Text => {
            let p = inspector.policy();
            writeln!(
                out,
                "policy: block_at={:?} warn_at={:?} redact={:?}",
                p.block_at, p.warn_at, p.redact
            )?;
            for r in inspector.rules() {
                writeln!(
                    out,
                    "{:<9} {:<10} {:<40} {}",
                    format!("{:?}", r.severity).to_lowercase(),
                    format!("{:?}", r.category).to_lowercase(),
                    r.id,
                    r.description
                )?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

impl RuleSource {
    fn build(&self) -> Result<Inspector> {
        let mut set = if self.no_defaults {
            RuleSet::default()
        } else {
            RuleSet::default_rules()
        };
        if let Some(p) = &self.rules {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading rules {}", p.display()))?;
            set.merge(RuleSet::from_toml(&text)?);
        }
        Ok(Inspector::new(set)?)
    }
}

fn read_input(path: Option<&Path>) -> Result<String> {
    match path {
        Some(p) if p.as_os_str() != "-" => {
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
        }
        _ => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("reading stdin")?;
            Ok(s)
        }
    }
}

fn parse_allow(spec: &str) -> Result<AllowList> {
    let (pointer, values) = spec
        .split_once('=')
        .with_context(|| format!("--allow `{spec}` must look like POINTER=v1,v2"))?;
    Ok(AllowList {
        pointer: pointer.to_owned(),
        values: values.split(',').map(str::to_owned).collect(),
    })
}

fn exit_for(decision: Decision) -> ExitCode {
    match decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Warn => ExitCode::from(EXIT_WARN),
        Decision::Block => ExitCode::from(EXIT_BLOCK),
    }
}
