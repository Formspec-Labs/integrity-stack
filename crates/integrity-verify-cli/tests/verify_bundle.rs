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
