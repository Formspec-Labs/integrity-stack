// Rust guideline compliant 2026-02-21
//! CLI argument parsing, dispatch, and output rendering.
//!
//! The CLI surface keeps a universal `verify <bundle.zip>` command and a
//! production `verify-export <bundle.zip>` command for Trellis/WOS export
//! bundles. Parsing is hand-rolled (no `clap` / `argh` dependency) to match
//! the dep-light posture of `integrity-stack/`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use integrity_bundle::{BundleEntry, read_stored_zip};
use integrity_verify::trellis::Severity;
use integrity_verify::{
    BundleEntryView, ProfileRegistry, SubstrateTier, VerificationReport, VerifyBundleInput,
    VerifyEvent, verify_universal,
};
use trellis_verify_wos::WosVerificationReport;

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
}

const CLI_SUBSTRATE_TIER_CEILING: SubstrateTier = SubstrateTier::L0;

const USAGE: &str = "\
usage: integrity-verify <command>

commands:
  verify <bundle.zip> [--format text|json|both]
  verify-export <bundle.zip> [--format text|json|both]

`verify` enumerates ZIP entries, parses each `.cbor` entry as a COSE_Sign1
envelope, runs the universal verifier (envelope shape, signature when public
keys are available, bundle structural ordering), and prints a
VerificationReport including substrate_tier. It does not register permissive
semantic profile shims; use `verify-export` for WOS/Trellis export semantics.

`verify-export` verifies a Trellis/WOS export ZIP through
trellis_verify_wos::verify_export_zip.

Exit code 0 on a verified report; exit code 1 on any failure.";

/// CLI top-level dispatcher.
///
/// `registry_factory` is a closure so tests can substitute a registry without
/// depending on a WOS profile plugin.
pub fn run(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    registry_factory: &dyn Fn() -> ProfileRegistry,
) -> Result<(), String> {
    let command = args.get(1).map(String::as_str).unwrap_or("");
    match command {
        "verify" => {
            let parsed = parse_verify_args(&args[2..])?;
            let registry = registry_factory();
            verify_command(&parsed, &registry, stdout)
        }
        "verify-export" => {
            let parsed = parse_verify_export_args(&args[2..])?;
            verify_export_command(&parsed, stdout)
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

#[derive(Debug)]
struct VerifyExportArgs {
    bundle_path: PathBuf,
    format: OutputFormat,
}

fn parse_verify_args(rest: &[String]) -> Result<VerifyArgs, String> {
    let mut bundle_path: Option<PathBuf> = None;
    let mut format = OutputFormat::Both;

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
    })
}

fn parse_verify_export_args(rest: &[String]) -> Result<VerifyExportArgs, String> {
    let mut bundle_path: Option<PathBuf> = None;
    let mut format = OutputFormat::Both;

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
    Ok(VerifyExportArgs {
        bundle_path,
        format,
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
        if is_candidate_event_path(entry) {
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

    if !report.universal_failures.is_empty()
        || !report.bundle_findings.is_empty()
        || !report.profile_verified
    {
        return Err(format!(
            "verification failed: substrate_tier={:?} universal_failures={} bundle_findings={} profile_verified={}",
            report.substrate_tier,
            report.universal_failures.len(),
            report.bundle_findings.len(),
            report.profile_verified
        ));
    }
    Ok(())
}

fn verify_export_command(args: &VerifyExportArgs, stdout: &mut dyn Write) -> Result<(), String> {
    let zip_bytes = fs::read(&args.bundle_path).map_err(|error| {
        format!(
            "failed to read bundle `{}`: {error}",
            args.bundle_path.display()
        )
    })?;
    let report = trellis_verify_wos::verify_export_zip(&zip_bytes);
    let text_section = render_export_text(&report);
    let json_section = render_export_json(&report)?;

    match args.format {
        OutputFormat::Text => stdout
            .write_all(text_section.as_bytes())
            .map_err(stdout_err)?,
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

    if export_failure_count(&report) != 0
        || !report.trellis.structure_verified
        || !report.trellis.integrity_verified
    {
        return Err(format!(
            "export verification failed: failures={}",
            export_failure_count(&report)
        ));
    }
    Ok(())
}

fn stdout_err(error: std::io::Error) -> String {
    format!("failed to write to stdout: {error}")
}

fn is_candidate_event_path(entry: &BundleEntry) -> bool {
    entry.path().ends_with(".cbor")
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
                "verifier_id".into(),
                serde_json::Value::String(r.verifier_id.clone()),
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

fn render_export_text(report: &WosVerificationReport) -> String {
    let mut out = String::new();
    out.push_str("integrity-verify export report\n");
    out.push_str(&format!(
        "  structure_verified: {}\n",
        report.trellis.structure_verified
    ));
    out.push_str(&format!(
        "  integrity_verified: {}\n",
        report.trellis.integrity_verified
    ));
    out.push_str(&format!(
        "  readability_verified: {}\n",
        report.trellis.readability_verified
    ));
    out.push_str(&format!(
        "  trellis_failures: {}\n",
        trellis_failure_count(report)
    ));
    out.push_str(&format!("  wos_findings: {}\n", report.wos_findings.len()));
    out.push_str(&format!("  wos_failures: {}\n", wos_failure_count(report)));
    for finding in &report.wos_findings {
        out.push_str(&format!(
            "    - severity={:?} kind={} message={}\n",
            finding.severity, finding.kind, finding.message
        ));
    }
    out
}

fn render_export_json(report: &WosVerificationReport) -> Result<String, String> {
    let mut root = serde_json::Map::new();
    root.insert(
        "structure_verified".into(),
        serde_json::Value::Bool(report.trellis.structure_verified),
    );
    root.insert(
        "integrity_verified".into(),
        serde_json::Value::Bool(report.trellis.integrity_verified),
    );
    root.insert(
        "readability_verified".into(),
        serde_json::Value::Bool(report.trellis.readability_verified),
    );
    root.insert(
        "trellis_failures".into(),
        serde_json::Value::Number(serde_json::Number::from(trellis_failure_count(report))),
    );
    root.insert(
        "wos_failures".into(),
        serde_json::Value::Number(serde_json::Number::from(wos_failure_count(report))),
    );
    root.insert(
        "verified".into(),
        serde_json::Value::Bool(
            report.trellis.structure_verified
                && report.trellis.integrity_verified
                && export_failure_count(report) == 0,
        ),
    );
    let wos_findings: Vec<serde_json::Value> = report
        .wos_findings
        .iter()
        .map(|finding| {
            let mut row = serde_json::Map::new();
            row.insert(
                "kind".into(),
                serde_json::Value::String(finding.kind.clone()),
            );
            row.insert(
                "severity".into(),
                serde_json::Value::String(format!("{:?}", finding.severity)),
            );
            row.insert(
                "message".into(),
                serde_json::Value::String(finding.message.clone()),
            );
            serde_json::Value::Object(row)
        })
        .collect();
    root.insert(
        "wos_findings".into(),
        serde_json::Value::Array(wos_findings),
    );

    serde_json::to_string_pretty(&serde_json::Value::Object(root))
        .map_err(|error| format!("failed to serialize export report JSON: {error}"))
}

fn export_failure_count(report: &WosVerificationReport) -> usize {
    trellis_failure_count(report) + wos_failure_count(report)
}

fn trellis_failure_count(report: &WosVerificationReport) -> usize {
    report.trellis.event_failures.len()
        + report.trellis.checkpoint_failures.len()
        + report.trellis.proof_failures.len()
}

fn wos_failure_count(report: &WosVerificationReport) -> usize {
    report
        .wos_findings
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signer, SigningKey};
    use integrity_bundle::{Bundle, BundleEntry};
    use integrity_cose::{protected_header_bytes, sig_structure_bytes, sign1_bytes};
    use integrity_verify::{ProfileVerificationResult, ProfileVerifier};

    struct CliVerifier {
        verified: bool,
    }

    impl ProfileVerifier for CliVerifier {
        fn verifier_id(&self) -> &str {
            "cli-default"
        }

        fn verify_profile_record(&self, _: &[u8], _: &[u8]) -> ProfileVerificationResult {
            if self.verified {
                ProfileVerificationResult::verified(self.verifier_id(), "ok")
            } else {
                ProfileVerificationResult::failed(
                    self.verifier_id(),
                    "failed",
                    vec!["profile rejected record".into()],
                )
            }
        }
    }

    fn signed_event(protected_header: Vec<u8>, payload: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let sig_struct = sig_structure_bytes(&protected_header, payload);
        let signature = signing_key.sign(&sig_struct);
        sign1_bytes(&protected_header, payload, signature.to_bytes())
    }

    fn retired_dispatch_header() -> Vec<u8> {
        vec![
            0xa4, 0x01, 0x27, 0x04, 0x50, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x3a,
            0x00, 0x01, 0x00, 0x02, 0x18, 0x63,
        ]
    }

    fn test_bundle_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "integrity-verify-cli-{name}-{}-{nonce}.zip",
            std::process::id()
        ))
    }

    fn write_test_bundle(name: &str, entries: &[(&str, Vec<u8>)]) -> PathBuf {
        let mut bundle = Bundle::new();
        for (path, bytes) in entries {
            bundle.add_entry(BundleEntry::new(*path, bytes.clone()));
        }
        let zip = bundle.to_zip_bytes().expect("test bundle should serialize");
        let path = test_bundle_path(name);
        std::fs::write(&path, zip).expect("test bundle should write");
        path
    }

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
        let args = parse_verify_args(&["/tmp/bundle.zip".into(), "--format".into(), "json".into()])
            .unwrap();
        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(args.bundle_path.to_str().unwrap(), "/tmp/bundle.zip");
    }

    #[test]
    fn verify_export_args_accept_flags() {
        let args =
            parse_verify_export_args(&["/tmp/bundle.zip".into(), "--format".into(), "json".into()])
                .unwrap();
        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(args.bundle_path.to_str().unwrap(), "/tmp/bundle.zip");
    }

    #[test]
    fn usage_declares_verify_export_command() {
        assert!(USAGE.contains("verify-export <bundle.zip>"));
    }

    #[test]
    fn run_help_command_succeeds() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let registry = || ProfileRegistry::new();
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
        let registry = || ProfileRegistry::new();
        let err = run(
            &["integrity-verify".into(), "explode".into()],
            &mut stdout,
            &mut stderr,
            &registry,
        )
        .unwrap_err();
        assert!(err.contains("unknown command"), "{err}");
    }

    #[test]
    fn verify_reports_retired_dispatch_label_as_failure() {
        let retired_event = signed_event(retired_dispatch_header(), b"payload");
        let bundle_path = write_test_bundle(
            "retired-dispatch-label",
            &[("events/0001.cbor", retired_event)],
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let registry = || ProfileRegistry::new();

        let result = run(
            &[
                "integrity-verify".into(),
                "verify".into(),
                bundle_path.display().to_string(),
                "--format".into(),
                "json".into(),
            ],
            &mut stdout,
            &mut stderr,
            &registry,
        );
        let _ = std::fs::remove_file(&bundle_path);

        let err = result.expect_err("retired dispatch label must fail verification");
        let output = String::from_utf8(stdout).expect("stdout should be UTF-8");
        assert!(err.contains("universal_failures=1"), "{err}");
        assert!(output.contains("RetiredDispatchLabelPresent"), "{output}");
        assert!(
            output.contains("\"kind\": \"malformed_envelope\""),
            "{output}"
        );
    }

    #[test]
    fn verify_fails_when_default_verifier_fails() {
        let event = signed_event(protected_header_bytes([0xab; 16]), b"payload");
        let bundle_path = write_test_bundle("profile-failure", &[("events/0001.cbor", event)]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let registry = || {
            let mut registry = ProfileRegistry::new();
            registry.register_default(Box::new(CliVerifier { verified: false }));
            registry
        };

        let result = run(
            &[
                "integrity-verify".into(),
                "verify".into(),
                bundle_path.display().to_string(),
                "--format".into(),
                "json".into(),
            ],
            &mut stdout,
            &mut stderr,
            &registry,
        );
        let _ = std::fs::remove_file(&bundle_path);

        let err = result.expect_err("profile verifier failure must fail the CLI");
        let output = String::from_utf8(stdout).expect("stdout should be UTF-8");
        assert!(err.contains("profile_verified=false"), "{err}");
        assert!(output.contains("\"profile_verified\": false"), "{output}");
        assert!(
            output.contains("\"verifier_id\": \"cli-default\""),
            "{output}"
        );
    }

    #[test]
    fn verify_json_uses_verifier_id() {
        let event = signed_event(protected_header_bytes([0xab; 16]), b"payload");
        let bundle_path = write_test_bundle("json-verifier-id", &[("events/0001.cbor", event)]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let registry = || {
            let mut registry = ProfileRegistry::new();
            registry.register_default(Box::new(CliVerifier { verified: true }));
            registry
        };

        run(
            &[
                "integrity-verify".into(),
                "verify".into(),
                bundle_path.display().to_string(),
                "--format".into(),
                "json".into(),
            ],
            &mut stdout,
            &mut stderr,
            &registry,
        )
        .expect("verified event should pass");
        let _ = std::fs::remove_file(&bundle_path);

        let output = String::from_utf8(stdout).expect("stdout should be UTF-8");
        assert!(
            output.contains("\"verifier_id\": \"cli-default\""),
            "{output}"
        );
        assert!(!output.contains("retired_dispatch"), "{output}");
    }
}
