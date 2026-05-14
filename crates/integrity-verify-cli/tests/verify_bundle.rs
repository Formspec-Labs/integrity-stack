// Rust guideline compliant 2026-02-21
//! Integration test: build a one-event bundle, run `integrity-verify verify`
//! against the resulting ZIP, assert substrate_tier surfaced and exit code 0.

use std::fs;
use std::process::Command;

use ed25519_dalek::{Signer, SigningKey};
use integrity_bundle::{Bundle, BundleEntry};
use integrity_cose::{protected_header_bytes_with_profile_id, sig_structure_bytes, sign1_bytes};

fn build_signed_event(seed: [u8; 32], profile_id: u64, payload: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&seed);
    let protected = protected_header_bytes_with_profile_id([0xab; 16], profile_id);
    let sig_struct = sig_structure_bytes(&protected, payload);
    let signature = signing_key.sign(&sig_struct);
    sign1_bytes(&protected, payload, signature.to_bytes())
}

fn write_temp_bundle(name: &str) -> std::path::PathBuf {
    let event_bytes = build_signed_event([0x12; 32], 1, b"cli-payload");
    let mut bundle = Bundle::new();
    bundle.add_entry(BundleEntry::new("010-event.cbor", event_bytes));
    let zip_bytes = bundle.to_zip_bytes().unwrap();
    let mut path = std::env::temp_dir();
    path.push(name);
    fs::write(&path, zip_bytes).unwrap();
    path
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
        stdout.contains("cli_tier_ceiling: L0"),
        "missing text ceiling: {stdout}"
    );
    assert!(
        stdout.contains("\"cli_tier_ceiling\": \"L0\""),
        "missing JSON ceiling: {stdout}"
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
    assert_eq!(tier.as_str(), Some("L0"));
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
