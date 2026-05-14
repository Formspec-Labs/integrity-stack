// Rust guideline compliant 2026-05-13
//! Parity harness for the verifier cutover gate.
//!
//! This crate runs an independent Trellis Python verifier projection and the
//! target `integrity_verify::trellis` implementation over the same export ZIP
//! bytes, then compares stable JSON-compatible projections.

#![forbid(unsafe_code)]

use std::{
    fmt,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    process::Command,
};

use ciborium::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

const COSE_SIGN1_TAG: u64 = 18;

/// Result of one independent-oracle-vs-target parity run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityReport {
    pub oracle: ReportProjection,
    pub target: ReportProjection,
    pub metadata: TargetMetadata,
    pub byte_identical: bool,
    pub diff: Option<String>,
}

/// Stable, JSON-compatible projection used for parity comparison.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReportProjection {
    pub structure_verified: bool,
    pub integrity_verified: bool,
    pub readability_verified: bool,
    pub event_failures: Vec<FailureProjection>,
    pub checkpoint_failures: Vec<FailureProjection>,
    pub proof_failures: Vec<FailureProjection>,
    pub posture_transition_count: usize,
    pub erasure_evidence_count: usize,
    pub certificates_of_completion_count: usize,
    pub user_content_attestation_count: usize,
    pub correction_preservation_count: usize,
    pub interop_sidecar_count: usize,
    pub posture_transitions: Vec<PostureTransitionProjection>,
    pub erasure_evidence: Vec<ErasureEvidenceProjection>,
    pub certificates_of_completion: Vec<CertificateProjection>,
    pub user_content_attestations: Vec<UserContentAttestationProjection>,
    pub correction_preservations: Vec<CorrectionPreservationProjection>,
    pub interop_sidecars: Vec<InteropSidecarProjection>,
    pub domain_findings: Vec<DomainFindingProjection>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substrate_tier: Option<String>,
}

/// Stable projection of one verifier failure row.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FailureProjection {
    pub kind: String,
    pub location: String,
}

/// Stable projection of one WOS/domain finding row.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DomainFindingProjection {
    pub kind: String,
    pub severity: String,
    pub message: String,
}

/// Stable projection of one posture-transition verifier outcome.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PostureTransitionProjection {
    pub transition_id: String,
    pub kind: String,
    pub event_index: u64,
    pub from_state: String,
    pub to_state: String,
    pub continuity_verified: bool,
    pub declaration_resolved: bool,
    pub attestations_verified: bool,
    pub failures: Vec<String>,
}

/// Stable projection of one erasure-evidence verifier outcome.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ErasureEvidenceProjection {
    pub evidence_id: String,
    pub kid_destroyed_hex: String,
    pub destroyed_at: String,
    pub event_index: u64,
    pub signature_verified: bool,
    pub post_erasure_uses: u64,
    pub post_erasure_wraps: u64,
    pub failures: Vec<String>,
}

/// Stable projection of one certificate-of-completion verifier outcome.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CertificateProjection {
    pub certificate_id: String,
    pub event_index: u64,
    pub signer_count: u64,
    pub attachment_resolved: bool,
    pub all_signing_events_resolved: bool,
    pub chain_summary_consistent: bool,
    pub failures: Vec<String>,
}

/// Stable projection of one user-content-attestation verifier outcome.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserContentAttestationProjection {
    pub attestation_id: String,
    pub attested_event_hash_hex: String,
    pub attestor: String,
    pub signing_intent: String,
    pub event_index: u64,
    pub chain_position_resolved: bool,
    pub identity_resolved: bool,
    pub signature_verified: bool,
    pub key_active: bool,
    pub failures: Vec<String>,
}

/// Stable projection of one correction-preservation verifier outcome.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CorrectionPreservationProjection {
    pub event_index: u64,
    pub correction_event_hash_hex: String,
    pub target_event_hash: Option<String>,
    pub corrected_field_set: Vec<String>,
    pub field_value_count: usize,
}

/// Stable projection of one interop-sidecar verifier outcome.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InteropSidecarProjection {
    pub kind: String,
    pub path: String,
    pub derivation_version: u8,
    pub content_digest_ok: bool,
    pub kind_registered: bool,
    pub phase_1_locked: bool,
    pub failures: Vec<String>,
}

/// Diagnostic metadata from the target-universal run.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct TargetMetadata {
    pub archive_entry_count: usize,
    pub target_event_count: usize,
    pub registry_key_count: usize,
    pub notes: Vec<String>,
}

/// Error returned when the independent parity harness cannot complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityError {
    message: String,
}

impl ParityError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Human-readable failure detail.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ParityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ParityError {}

/// Runs the independent Python oracle and target verifier over one fixture ZIP,
/// then compares their stable projections.
///
/// # Errors
/// Returns an error when the fixture cannot be read, the Python oracle cannot
/// be executed, or the oracle emits an invalid projection.
pub fn run_parity_for_fixture(fixture_path: impl AsRef<Path>) -> Result<ParityReport, ParityError> {
    let fixture_path = fixture_path.as_ref();
    let fixture_bytes = std::fs::read(fixture_path).map_err(|error| {
        ParityError::new(format!("read fixture {}: {error}", fixture_path.display()))
    })?;
    let oracle = run_python_oracle(fixture_path)?;
    let (target, metadata) = run_target(fixture_bytes);
    let oracle_canonical = canonical_report_bytes(&oracle);
    let target_canonical = canonical_report_bytes(&target);
    let byte_identical = oracle_canonical == target_canonical;
    let diff = (!byte_identical).then(|| compute_diff(&oracle_canonical, &target_canonical));

    Ok(ParityReport {
        oracle,
        target,
        metadata,
        byte_identical,
        diff,
    })
}

/// Returns canonical JSON bytes for a report projection. The only intentionally
/// target-new field stripped today is `substrate_tier`.
#[must_use]
pub fn canonical_report_bytes(report: &ReportProjection) -> Vec<u8> {
    let mut value = serde_json::to_value(report).expect("report projection serializes to JSON");
    strip_intentional_new_fields(&mut value);
    serde_json::to_vec(&value).expect("canonical report JSON serializes")
}

fn project_target(report: integrity_verify::trellis::VerificationWithDomain) -> ReportProjection {
    let trellis = report.trellis;
    let posture_transitions = trellis
        .posture_transitions
        .iter()
        .map(|outcome| PostureTransitionProjection {
            transition_id: outcome.transition_id.clone(),
            kind: outcome.kind.clone(),
            event_index: outcome.event_index,
            from_state: outcome.from_state.clone(),
            to_state: outcome.to_state.clone(),
            continuity_verified: outcome.continuity_verified,
            declaration_resolved: outcome.declaration_resolved,
            attestations_verified: outcome.attestations_verified,
            failures: outcome.failures.clone(),
        })
        .collect();
    let erasure_evidence = trellis
        .erasure_evidence
        .iter()
        .map(|outcome| ErasureEvidenceProjection {
            evidence_id: outcome.evidence_id.clone(),
            kid_destroyed_hex: hex_bytes(&outcome.kid_destroyed),
            destroyed_at: outcome.destroyed_at.to_string(),
            event_index: outcome.event_index,
            signature_verified: outcome.signature_verified,
            post_erasure_uses: outcome.post_erasure_uses,
            post_erasure_wraps: outcome.post_erasure_wraps,
            failures: outcome.failures.clone(),
        })
        .collect();
    let certificates_of_completion = trellis
        .certificates_of_completion
        .iter()
        .map(|outcome| CertificateProjection {
            certificate_id: outcome.certificate_id.clone(),
            event_index: outcome.event_index,
            signer_count: outcome.signer_count,
            attachment_resolved: outcome.attachment_resolved,
            all_signing_events_resolved: outcome.all_signing_events_resolved,
            chain_summary_consistent: outcome.chain_summary_consistent,
            failures: outcome.failures.clone(),
        })
        .collect();
    let user_content_attestations = trellis
        .user_content_attestations
        .iter()
        .map(|outcome| UserContentAttestationProjection {
            attestation_id: outcome.attestation_id.clone(),
            attested_event_hash_hex: hex_bytes(&outcome.attested_event_hash),
            attestor: outcome.attestor.clone(),
            signing_intent: outcome.signing_intent.clone(),
            event_index: outcome.event_index,
            chain_position_resolved: outcome.chain_position_resolved,
            identity_resolved: outcome.identity_resolved,
            signature_verified: outcome.signature_verified,
            key_active: outcome.key_active,
            failures: outcome.failures.clone(),
        })
        .collect();
    let correction_preservations = trellis
        .correction_preservations
        .iter()
        .map(|outcome| CorrectionPreservationProjection {
            event_index: outcome.event_index,
            correction_event_hash_hex: hex_bytes(&outcome.correction_event_hash),
            target_event_hash: outcome.target_event_hash.clone(),
            corrected_field_set: outcome.corrected_field_set.clone(),
            field_value_count: outcome.field_values.len(),
        })
        .collect();
    let interop_sidecars = trellis
        .interop_sidecars
        .iter()
        .map(|outcome| InteropSidecarProjection {
            kind: outcome.kind.clone(),
            path: outcome.path.clone(),
            derivation_version: outcome.derivation_version,
            content_digest_ok: outcome.content_digest_ok,
            kind_registered: outcome.kind_registered,
            phase_1_locked: outcome.phase_1_locked,
            failures: outcome.failures.clone(),
        })
        .collect();

    ReportProjection {
        structure_verified: trellis.structure_verified,
        integrity_verified: trellis.integrity_verified,
        readability_verified: trellis.readability_verified,
        event_failures: trellis
            .event_failures
            .iter()
            .map(|failure| FailureProjection {
                kind: failure.kind.as_str().to_string(),
                location: failure.location.clone(),
            })
            .collect(),
        checkpoint_failures: trellis
            .checkpoint_failures
            .iter()
            .map(|failure| FailureProjection {
                kind: failure.kind.as_str().to_string(),
                location: failure.location.clone(),
            })
            .collect(),
        proof_failures: trellis
            .proof_failures
            .iter()
            .map(|failure| FailureProjection {
                kind: failure.kind.as_str().to_string(),
                location: failure.location.clone(),
            })
            .collect(),
        posture_transition_count: trellis.posture_transitions.len(),
        erasure_evidence_count: trellis.erasure_evidence.len(),
        certificates_of_completion_count: trellis.certificates_of_completion.len(),
        user_content_attestation_count: trellis.user_content_attestations.len(),
        correction_preservation_count: trellis.correction_preservations.len(),
        interop_sidecar_count: trellis.interop_sidecars.len(),
        posture_transitions,
        erasure_evidence,
        certificates_of_completion,
        user_content_attestations,
        correction_preservations,
        interop_sidecars,
        domain_findings: report
            .domain_findings
            .iter()
            .map(|finding| DomainFindingProjection {
                kind: finding.kind.clone(),
                severity: format!("{:?}", finding.severity).to_ascii_lowercase(),
                message: finding.message.clone(),
            })
            .collect(),
        warnings: trellis.warnings,
        substrate_tier: None,
    }
}

fn run_target(fixture_bytes: Vec<u8>) -> (ReportProjection, TargetMetadata) {
    let report = integrity_verify::trellis::verify_export_zip_with_validator(
        &fixture_bytes,
        &trellis_verify_wos::WosRecordValidator,
    );
    (project_target(report), collect_metadata(&fixture_bytes))
}

fn run_python_oracle(fixture_path: &Path) -> Result<ReportProjection, ParityError> {
    let trellis_root = trellis_repo_root();
    let mut command = Command::new("uv");
    command
        .arg("run")
        .arg("--with")
        .arg("cbor2")
        .arg("--with")
        .arg("cryptography")
        .arg("python")
        .arg("-m")
        .arg("trellis_py.parity_oracle")
        .arg(fixture_path)
        .current_dir(&trellis_root)
        .env("PYTHONPATH", trellis_root.join("trellis-py/src"));

    let output = command.output().map_err(|error| {
        ParityError::new(format!(
            "run Python verifier oracle for {}: {error}",
            fixture_path.display()
        ))
    })?;
    if !output.status.success() {
        return Err(ParityError::new(format!(
            "Python verifier oracle failed for {} with status {}\nstdout:\n{}\nstderr:\n{}",
            fixture_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        ParityError::new(format!(
            "decode Python verifier oracle JSON for {}: {error}\nstdout:\n{}",
            fixture_path.display(),
            String::from_utf8_lossy(&output.stdout)
        ))
    })
}

fn trellis_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../trellis")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArchiveMember {
    path: String,
    bytes: Vec<u8>,
}

fn read_export_archive(bytes: &[u8]) -> Result<Vec<ArchiveMember>, String> {
    let cursor = Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|error| format!("failed to open ZIP: {error}"))?;
    let mut members = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("failed to read ZIP member {index}: {error}"))?;
        if file.is_dir() {
            continue;
        }
        let mut member_bytes = Vec::new();
        file.read_to_end(&mut member_bytes)
            .map_err(|error| format!("failed to read ZIP member {}: {error}", file.name()))?;
        members.push(ArchiveMember {
            path: relative_member_path(file.name()),
            bytes: member_bytes,
        });
    }
    Ok(members)
}

fn relative_member_path(path: &str) -> String {
    path.split_once('/')
        .and_then(|(_, rest)| (!rest.is_empty()).then_some(rest))
        .unwrap_or(path)
        .to_string()
}

fn collect_metadata(bytes: &[u8]) -> TargetMetadata {
    let mut metadata = TargetMetadata::default();
    let members = match read_export_archive(bytes) {
        Ok(members) => members,
        Err(error) => {
            metadata.notes.push(error);
            return metadata;
        }
    };
    metadata.archive_entry_count = members.len();
    match count_signing_registry_keys(&members) {
        Ok(count) => metadata.registry_key_count = count,
        Err(error) => metadata.notes.push(error),
    }
    for member in &members {
        if member.path.ends_with(".cbor") {
            match extract_cose_sign1_bytes(&member.bytes) {
                Ok(events) => metadata.target_event_count += events.len(),
                Err(error) => metadata.notes.push(format!(
                    "{}: skipped as non-COSE CBOR ({error})",
                    member.path
                )),
            }
        }
    }
    metadata
}

fn count_signing_registry_keys(members: &[ArchiveMember]) -> Result<usize, String> {
    let registry_member = members
        .iter()
        .find(|member| member.path == "030-signing-key-registry.cbor")
        .ok_or_else(|| "target path could not find 030-signing-key-registry.cbor".to_string())?;
    let value = decode_cbor_value(&registry_member.bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| "signing-key registry root is not an array".to_string())?;
    let mut count = 0;
    for entry in entries {
        let Some(map) = entry.as_map() else {
            continue;
        };
        let kind = map_lookup_text(map, "kind");
        let kind = kind.as_deref().map(|value| match value {
            "wrap" => "subject",
            other => other,
        });
        if matches!(kind, None | Some("signing")) {
            if map_lookup_bytes(map, "kid").is_none() {
                continue;
            }
            let Some(pubkey) = map_lookup_bytes(map, "pubkey") else {
                continue;
            };
            if <[u8; 32]>::try_from(pubkey.as_slice()).is_ok() {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn extract_cose_sign1_bytes(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let value = decode_cbor_value(bytes)?;
    match &value {
        Value::Tag(tag, _) if *tag == COSE_SIGN1_TAG => Ok(vec![bytes.to_vec()]),
        Value::Array(items) => {
            let mut events = Vec::new();
            for item in items {
                if let Value::Tag(tag, _) = item
                    && *tag == COSE_SIGN1_TAG
                {
                    let mut encoded = Vec::new();
                    ciborium::into_writer(item, &mut encoded)
                        .map_err(|error| format!("failed to re-encode COSE_Sign1: {error}"))?;
                    events.push(encoded);
                }
            }
            Ok(events)
        }
        _ => Ok(Vec::new()),
    }
}

fn decode_cbor_value(bytes: &[u8]) -> Result<Value, String> {
    let mut reader = bytes;
    let value: Value = ciborium::from_reader(&mut reader)
        .map_err(|error| format!("CBOR decode failed: {error}"))?;
    if !reader.is_empty() {
        return Err("trailing bytes after CBOR value".to_string());
    }
    Ok(value)
}

fn map_lookup_text(map: &[(Value, Value)], key_name: &str) -> Option<String> {
    map.iter()
        .find(|(key, _)| key.as_text().is_some_and(|key| key == key_name))
        .and_then(|(_, value)| value.as_text().map(ToString::to_string))
}

fn map_lookup_bytes(map: &[(Value, Value)], key_name: &str) -> Option<Vec<u8>> {
    map.iter()
        .find(|(key, _)| key.as_text().is_some_and(|key| key == key_name))
        .and_then(|(_, value)| value.as_bytes().cloned())
}

fn strip_intentional_new_fields(value: &mut JsonValue) {
    match value {
        JsonValue::Object(object) => {
            object.remove("substrate_tier");
            for child in object.values_mut() {
                strip_intentional_new_fields(child);
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                strip_intentional_new_fields(item);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
    }
}

fn compute_diff(oracle: &[u8], target: &[u8]) -> String {
    let oracle_pretty = pretty_json_bytes(oracle);
    let target_pretty = pretty_json_bytes(target);
    let oracle_lines: Vec<&str> = oracle_pretty.lines().collect();
    let target_lines: Vec<&str> = target_pretty.lines().collect();
    let max_len = oracle_lines.len().max(target_lines.len());
    let mut rows = Vec::new();
    for index in 0..max_len {
        let left = oracle_lines.get(index).copied().unwrap_or("");
        let right = target_lines.get(index).copied().unwrap_or("");
        if left != right {
            rows.push(format!(
                "line {}:\n  oracle: {left}\n  target: {right}",
                index + 1
            ));
        }
        if rows.len() == 12 {
            rows.push("diff truncated after 12 changed lines".to_string());
            break;
        }
    }
    rows.join("\n")
}

fn pretty_json_bytes(bytes: &[u8]) -> String {
    let value: JsonValue = serde_json::from_slice(bytes).expect("canonical JSON parses");
    serde_json::to_string_pretty(&value).expect("pretty JSON serializes")
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}
