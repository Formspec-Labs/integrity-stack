// Rust guideline compliant 2026-02-21
//! CLI argument parsing, dispatch, and output rendering.
//!
//! The CLI surface is a single subcommand `verify <bundle.zip>` with a small
//! set of flags. Parsing is hand-rolled (no `clap` / `argh` dependency) to
//! match the dep-light posture of `integrity-stack/`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use integrity_bundle::{BundleEntry, read_stored_zip};
use integrity_cose::decode_cose_sign1;
use integrity_verify::{
    BundleEntryView, ProfileRegistry, SubstrateTier, VerificationReport, VerifyBundleInput,
    VerifyEvent, verify_universal,
};

/// Output format selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Both,
}

impl OutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "unknown --format value `{other}` (expected text|json|both)"
            )),
        }
    }
}

/// Parsed `verify` subcommand options.
#[derive(Debug)]
pub struct VerifyArgs {
    pub bundle_path: PathBuf,
    pub format: OutputFormat,
    pub profile_override: Option<u64>,
}

const CLI_SUBSTRATE_TIER_CEILING: SubstrateTier = SubstrateTier::L0;

const USAGE: &str = "\
usage: integrity-verify verify <bundle.zip> [--format text|json|both] [--profile <id>]

Verifies an offline integrity bundle: enumerates ZIP entries, parses each
`.cbor` entry as a COSE_Sign1 envelope, runs the universal verifier
(envelope shape, signature when public keys are available, bundle structural
ordering), and prints a VerificationReport including substrate_tier.

This standalone ZIP command currently supplies envelope events and bundle
paths only. It does not ingest chain-continuity rows or external witness
evidence, so its effective substrate_tier ceiling is L0 even though the shared
report enum is the full L0..L3 ladder per CP §2.4.

Exit code 0 on a non-None substrate_tier with no universal failures; exit
code 1 on any failure.";

/// CLI top-level dispatcher.
///
/// `registry_factory` is a closure so tests can substitute a registry that
/// registers `AlwaysOk(profile_id)` verifiers without depending on a future
/// WOS profile plugin.
pub fn run(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    registry_factory: &dyn Fn(Option<u64>) -> ProfileRegistry,
) -> Result<(), String> {
    let command = args.get(1).map(String::as_str).unwrap_or("");
    match command {
        "verify" => {
            let parsed = parse_verify_args(&args[2..])?;
            let registry = registry_factory(parsed.profile_override);
            verify_command(&parsed, &registry, stdout)
        }
        "help" | "--help" | "-h" | "" => {
            let _ = stderr.write_all(USAGE.as_bytes());
            let _ = stderr.write_all(b"\n");
            Ok(())
        }
        other => Err(format!(
            "unknown command `{other}` — run `integrity-verify --help` for usage"
        )),
    }
}

fn parse_verify_args(rest: &[String]) -> Result<VerifyArgs, String> {
    let mut bundle_path: Option<PathBuf> = None;
    let mut format = OutputFormat::Both;
    let mut profile_override: Option<u64> = None;

    let mut index = 0;
    while index < rest.len() {
        let token = &rest[index];
        match token.as_str() {
            "--format" => {
                let value = rest
                    .get(index + 1)
                    .ok_or_else(|| "--format requires a value".to_string())?;
                format = OutputFormat::parse(value)?;
                index += 2;
            }
            "--profile" => {
                let value = rest
                    .get(index + 1)
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                profile_override = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("--profile value `{value}` is not a u64"))?,
                );
                index += 2;
            }
            "--help" | "-h" => {
                return Err(USAGE.to_string());
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag `{other}`"));
            }
            _ => {
                if bundle_path.is_some() {
                    return Err(format!("unexpected positional argument `{token}`"));
                }
                bundle_path = Some(PathBuf::from(token));
                index += 1;
            }
        }
    }
    let bundle_path = bundle_path.ok_or_else(|| USAGE.to_string())?;
    Ok(VerifyArgs {
        bundle_path,
        format,
        profile_override,
    })
}

fn verify_command(
    args: &VerifyArgs,
    registry: &ProfileRegistry,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    let zip_bytes = fs::read(&args.bundle_path).map_err(|error| {
        format!(
            "failed to read bundle `{}`: {error}",
            args.bundle_path.display()
        )
    })?;
    let entries = read_stored_zip(&zip_bytes)
        .map_err(|error| format!("failed to parse bundle ZIP: {error}"))?;

    let mut event_indices: Vec<usize> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if is_candidate_event(entry) {
            event_indices.push(index);
        }
    }

    let bundle_views: Vec<BundleEntryView<'_>> = entries
        .iter()
        .map(|entry| BundleEntryView { path: entry.path() })
        .collect();

    let verify_events: Vec<VerifyEvent<'_>> = event_indices
        .iter()
        .map(|&i| VerifyEvent {
            sign1_bytes: entries[i].bytes(),
            public_key: None,
            detached_payload: None,
        })
        .collect();

    let input = VerifyBundleInput {
        events: verify_events.as_slice(),
        bundle_entries: Some(bundle_views.as_slice()),
        chain_events: None,
        canonical_digest_check: None,
    };
    let report = verify_universal(&input, registry);

    let text_section = render_text(&report, &event_indices, &entries);
    let json_section = render_json(&report)?;

    match args.format {
        OutputFormat::Text => {
            stdout
                .write_all(text_section.as_bytes())
                .map_err(stdout_err)?;
        }
        OutputFormat::Json => {
            stdout
                .write_all(json_section.as_bytes())
                .map_err(stdout_err)?;
            stdout.write_all(b"\n").map_err(stdout_err)?;
        }
        OutputFormat::Both => {
            stdout
                .write_all(text_section.as_bytes())
                .map_err(stdout_err)?;
            stdout.write_all(b"\n").map_err(stdout_err)?;
            stdout
                .write_all(json_section.as_bytes())
                .map_err(stdout_err)?;
            stdout.write_all(b"\n").map_err(stdout_err)?;
        }
    }

    if report.substrate_tier.is_none() || !report.universal_failures.is_empty() {
        return Err(format!(
            "verification failed: substrate_tier={:?} universal_failures={}",
            report.substrate_tier,
            report.universal_failures.len()
        ));
    }
    Ok(())
}

fn stdout_err(error: std::io::Error) -> String {
    format!("failed to write to stdout: {error}")
}

fn is_candidate_event(entry: &BundleEntry) -> bool {
    if !entry.path().ends_with(".cbor") {
        return false;
    }
    decode_cose_sign1(entry.bytes()).is_ok()
}

fn render_text(
    report: &VerificationReport,
    event_indices: &[usize],
    entries: &[BundleEntry],
) -> String {
    let tier = report
        .substrate_tier
        .map(SubstrateTier::as_str)
        .unwrap_or("none");
    let mut out = String::new();
    out.push_str("integrity-verify report\n");
    out.push_str(&format!("  substrate_tier: {tier}\n"));
    out.push_str(&format!(
        "  cli_tier_ceiling: {}\n",
        CLI_SUBSTRATE_TIER_CEILING.as_str()
    ));
    out.push_str(&format!(
        "  universal_verified: {}\n",
        report.universal_verified
    ));
    out.push_str(&format!(
        "  profile_verified: {}\n",
        report.profile_verified
    ));
    out.push_str(&format!("  bundle_entries: {}\n", entries.len()));
    out.push_str(&format!("  signed_events: {}\n", event_indices.len()));
    out.push_str(&format!("  bundle_checked: {}\n", report.bundle_checked));
    out.push_str(&format!("  chain_checked: {}\n", report.chain_checked));
    out.push_str(&format!(
        "  canonical_checked: {}\n",
        report.canonical_checked
    ));
    out.push_str(&format!(
        "  universal_failures: {}\n",
        report.universal_failures.len()
    ));
    for failure in &report.universal_failures {
        out.push_str(&format!(
            "    - kind={} event_index={} message={}\n",
            failure.kind.as_str(),
            failure.event_index,
            failure.message
        ));
    }
    out.push_str(&format!(
        "  bundle_findings: {}\n",
        report.bundle_findings.len()
    ));
    for finding in &report.bundle_findings {
        out.push_str(&format!(
            "    - kind={} entry_index={} message={}\n",
            finding.kind, finding.entry_index, finding.message
        ));
    }
    out.push_str(&format!(
        "  profile_results: {} (verified={})\n",
        report.profile_results.len(),
        report.profile_results.iter().filter(|r| r.verified).count()
    ));
    out
}

fn render_json(report: &VerificationReport) -> Result<String, String> {
    let mut root = serde_json::Map::new();
    root.insert(
        "substrate_tier".into(),
        match report.substrate_tier {
            Some(tier) => serde_json::Value::String(tier.as_str().into()),
            None => serde_json::Value::Null,
        },
    );
    root.insert(
        "cli_tier_ceiling".into(),
        serde_json::Value::String(CLI_SUBSTRATE_TIER_CEILING.as_str().into()),
    );
    root.insert(
        "universal_verified".into(),
        serde_json::Value::Bool(report.universal_verified),
    );
    root.insert(
        "profile_verified".into(),
        serde_json::Value::Bool(report.profile_verified),
    );
    root.insert(
        "bundle_checked".into(),
        serde_json::Value::Bool(report.bundle_checked),
    );
    root.insert(
        "chain_checked".into(),
        serde_json::Value::Bool(report.chain_checked),
    );
    root.insert(
        "canonical_checked".into(),
        serde_json::Value::Bool(report.canonical_checked),
    );

    let failures: Vec<serde_json::Value> = report
        .universal_failures
        .iter()
        .map(|f| {
            let mut row = serde_json::Map::new();
            row.insert(
                "kind".into(),
                serde_json::Value::String(f.kind.as_str().into()),
            );
            row.insert(
                "event_index".into(),
                serde_json::Value::Number(serde_json::Number::from(f.event_index as u64)),
            );
            row.insert(
                "message".into(),
                serde_json::Value::String(f.message.clone()),
            );
            serde_json::Value::Object(row)
        })
        .collect();
    root.insert(
        "universal_failures".into(),
        serde_json::Value::Array(failures),
    );

    let bundle_findings: Vec<serde_json::Value> = report
        .bundle_findings
        .iter()
        .map(|f| {
            let mut row = serde_json::Map::new();
            row.insert("kind".into(), serde_json::Value::String(f.kind.into()));
            row.insert(
                "entry_index".into(),
                serde_json::Value::Number(serde_json::Number::from(f.entry_index as u64)),
            );
            row.insert(
                "message".into(),
                serde_json::Value::String(f.message.clone()),
            );
            serde_json::Value::Object(row)
        })
        .collect();
    root.insert(
        "bundle_findings".into(),
        serde_json::Value::Array(bundle_findings),
    );

    let profile_results: Vec<serde_json::Value> = report
        .profile_results
        .iter()
        .map(|r| {
            let mut row = serde_json::Map::new();
            row.insert(
                "profile_id".into(),
                serde_json::Value::Number(serde_json::Number::from(r.profile_id)),
            );
            row.insert(
                "verdict".into(),
                serde_json::Value::String(r.verdict.clone()),
            );
            row.insert("verified".into(), serde_json::Value::Bool(r.verified));
            let findings: Vec<serde_json::Value> = r
                .findings
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect();
            row.insert("findings".into(), serde_json::Value::Array(findings));
            serde_json::Value::Object(row)
        })
        .collect();
    root.insert(
        "profile_results".into(),
        serde_json::Value::Array(profile_results),
    );

    serde_json::to_string_pretty(&serde_json::Value::Object(root))
        .map_err(|error| format!("failed to serialize report JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_tokens() {
        assert_eq!(OutputFormat::parse("text").unwrap(), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("both").unwrap(), OutputFormat::Both);
        assert!(OutputFormat::parse("yaml").is_err());
    }

    #[test]
    fn verify_args_require_bundle_path() {
        let err = parse_verify_args(&[]).unwrap_err();
        assert!(err.contains("usage:"), "{err}");
    }

    #[test]
    fn verify_args_accept_flags() {
        let args = parse_verify_args(&[
            "/tmp/bundle.zip".into(),
            "--format".into(),
            "json".into(),
            "--profile".into(),
            "1".into(),
        ])
        .unwrap();
        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(args.profile_override, Some(1));
        assert_eq!(args.bundle_path.to_str().unwrap(), "/tmp/bundle.zip");
    }

    #[test]
    fn usage_declares_standalone_tier_ceiling() {
        assert!(USAGE.contains("effective substrate_tier ceiling is L0"));
    }

    #[test]
    fn run_help_command_succeeds() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let registry = |_| ProfileRegistry::new();
        run(
            &["integrity-verify".into(), "--help".into()],
            &mut stdout,
            &mut stderr,
            &registry,
        )
        .unwrap();
        assert!(String::from_utf8(stderr).unwrap().contains("usage"));
    }

    #[test]
    fn run_rejects_unknown_command() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let registry = |_| ProfileRegistry::new();
        let err = run(
            &["integrity-verify".into(), "explode".into()],
            &mut stdout,
            &mut stderr,
            &registry,
        )
        .unwrap_err();
        assert!(err.contains("unknown command"), "{err}");
    }
}
