// Rust guideline compliant 2026-02-21
//! Integration tests for the offline verifier CLI.

use std::fs;
use std::process::Command;

use integrity_bundle::{Bundle, BundleEntry};

fn write_temp_bundle(name: &str) -> std::path::PathBuf {
    let mut bundle = Bundle::new();
    bundle.add_entry(BundleEntry::new(
        "000-readme.txt",
        b"bundle metadata".to_vec(),
    ));
    let zip_bytes = bundle.to_zip_bytes().unwrap();
    let mut path = std::env::temp_dir();
    path.push(name);
    fs::write(&path, zip_bytes).unwrap();
    path
}

fn trellis_export_fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../trellis/fixtures/vectors/export/001-two-event-chain/expected-export.zip")
}

#[test]
fn verify_command_reports_substrate_tier_and_exits_zero() {
    let bundle_path = write_temp_bundle("integrity-verify-cli-it-substrate-tier.zip");
    let binary = env!("CARGO_BIN_EXE_integrity-verify");
    let output = Command::new(binary)
        .arg("verify")
        .arg(&bundle_path)
        .output()
        .expect("failed to spawn integrity-verify binary");
    let _ = fs::remove_file(&bundle_path);

    assert!(
        output.status.success(),
        "binary exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    assert!(
        stdout.contains("substrate_tier"),
        "stdout missing substrate_tier token: {stdout}"
    );
    // Must produce both the text section and the JSON section by default.
    assert!(
        stdout.contains("integrity-verify report"),
        "missing text header: {stdout}"
    );
    assert!(
        stdout.contains("\"substrate_tier\""),
        "missing JSON field: {stdout}"
    );
    assert!(
        stdout.contains("substrate_tier: none"),
        "missing text tier: {stdout}"
    );
    assert!(
        stdout.contains("\"substrate_tier\": null"),
        "missing JSON tier: {stdout}"
    );
}

#[test]
fn verify_command_json_only_format() {
    let bundle_path = write_temp_bundle("integrity-verify-cli-it-json-only.zip");
    let binary = env!("CARGO_BIN_EXE_integrity-verify");
    let output = Command::new(binary)
        .arg("verify")
        .arg(&bundle_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to spawn integrity-verify binary");
    let _ = fs::remove_file(&bundle_path);

    assert!(output.status.success(), "binary exited non-zero");
    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("stdout was not valid JSON: {err}\n{stdout}"));
    let tier = value
        .get("substrate_tier")
        .expect("missing substrate_tier field");
    assert!(tier.is_null(), "expected no tier for bundle-only input");
    assert_eq!(
        value
            .get("cli_tier_ceiling")
            .and_then(serde_json::Value::as_str),
        Some("L0")
    );
}

#[test]
fn verify_command_fails_on_missing_bundle() {
    let binary = env!("CARGO_BIN_EXE_integrity-verify");
    let output = Command::new(binary)
        .arg("verify")
        .arg("/tmp/does-not-exist-integrity-verify-cli.zip")
        .output()
        .expect("failed to spawn integrity-verify binary");
    assert!(
        !output.status.success(),
        "missing-bundle case should fail; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn verify_export_command_reports_wos_export_summary() {
    let binary = env!("CARGO_BIN_EXE_integrity-verify");
    let output = Command::new(binary)
        .arg("verify-export")
        .arg(trellis_export_fixture())
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to spawn integrity-verify binary");

    assert!(
        output.status.success(),
        "binary exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("stdout was not valid JSON: {err}\n{stdout}"));
    assert_eq!(value["signing_key_registry_pin"]["status"], "not_requested");
    assert!(value["signing_key_registry_pin"]["expected_sha256"].is_null());
    assert_eq!(
        value.get("verified").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .get("wos_failures")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
}

// Fixture 001's committed registry snapshot, independently retained for this
// synthetic test. Production selection must come from outside the archive.
const FIXTURE_REGISTRY_SHA256: &str =
    "5fb219dd247fab84a0c747ca1cfe1ac1431f226d52ca0f4eab80c92df1dc1ada";

#[test]
fn verify_export_accepts_selected_snapshot_and_refuses_foreign_snapshot() {
    let binary = env!("CARGO_BIN_EXE_integrity-verify");
    for (digest, expected_success) in [
        (FIXTURE_REGISTRY_SHA256, true),
        // Fixture005 is internally valid but carries a different registry.
        (
            "ba3614ce043b40176d23d57bb26defe1c1f76a669a3aff619ee360ddf366a1f3",
            false,
        ),
    ] {
        let output = Command::new(binary)
            .arg("verify-export")
            .arg(trellis_export_fixture())
            .args([
                "--format",
                "json",
                "--trusted-signing-key-registry-sha256",
                digest,
            ])
            .output()
            .expect("failed to spawn verifier");
        assert_eq!(output.status.success(), expected_success);
        if expected_success {
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["verified"], true);
            assert_eq!(report["signing_key_registry_pin"]["status"], "matched");
            assert_eq!(
                report["signing_key_registry_pin"]["expected_sha256"],
                digest
            );
            assert_eq!(
                report["signing_key_registry_pin"]["observed_sha256"],
                digest
            );
        } else {
            assert!(
                output.stdout.is_empty(),
                "mismatch must not publish a success report"
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("registry pin mismatch"));
        }
    }
}
