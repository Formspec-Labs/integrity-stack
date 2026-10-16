//! Indexed completion v2 checks and unchanged completion v1 compatibility.

use super::certificate::{
    certificate_catalog_row_matches_details, finalize_certificates_of_completion,
};
use super::certificate_proof::{
    CertificateResponseProof, NoopResponseProofResolver, ResolverError, ResponseProofResolver,
};
use super::parse::{decode_certificate_payload, decode_event_details, decode_value};
use super::*;
use ciborium::Value;
use integrity_seam::{OsSecureRandom, SecureRandom};

fn field<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value)
        .unwrap()
}
fn set(value: &mut Value, name: &str, replacement: Value) {
    let map = value.as_map_mut().unwrap();
    if let Some((_, target)) = map.iter_mut().find(|(key, _)| key.as_text() == Some(name)) {
        *target = replacement;
    } else {
        map.push((Value::Text(name.into()), replacement));
    }
}
fn remove(value: &mut Value, name: &str) {
    value
        .as_map_mut()
        .unwrap()
        .retain(|(key, _)| key.as_text() != Some(name));
}
fn fixture() -> (EventDetails, Value) {
    let event = parse_sign1_bytes(include_bytes!(
        "../../tests/fixtures/native-external/certificate-event.cbor"
    ))
    .unwrap();
    let details = decode_event_details(&event).unwrap();
    let mut value = decode_value(event.payload.as_ref().unwrap()).unwrap();
    let certificate = field(field(&mut value, "extensions"), CERTIFICATE_EVENT_EXTENSION).clone();
    (details, certificate)
}
fn v2_wire() -> Value {
    let (_, mut certificate) = fixture();
    let summary = field(&mut certificate, "chain_summary");
    remove(summary, "response_ref");
    set(summary, "signer_count", Value::Integer(2.into()));
    set(summary, "covered_claims", Value::Array(vec![]));
    let mut first = field(summary, "signer_display").as_array().unwrap()[0].clone();
    set(
        &mut first,
        "principal_ref",
        Value::Text("urn:test:signer:1".into()),
    );
    set(&mut first, "response_ref", Value::Bytes(vec![0xcc; 32]));
    let mut second = first.clone();
    set(
        &mut second,
        "principal_ref",
        Value::Text("urn:test:signer:2".into()),
    );
    set(&mut second, "response_ref", Value::Bytes(vec![0xdd; 32]));
    set(summary, "signer_display", Value::Array(vec![first, second]));
    set(
        &mut certificate,
        "signing_events",
        Value::Array(vec![Value::Bytes(vec![1; 32]), Value::Bytes(vec![2; 32])]),
    );
    certificate
}
fn decode(wire: &Value, extension: &str) -> Result<CertificateDetails, VerifyError> {
    decode_certificate_payload(&[(Value::Text(extension.into()), wire.clone())]).map(|v| v.unwrap())
}
fn pool(certificate: &CertificateDetails) -> Vec<EventDetails> {
    let (template, _) = fixture();
    certificate
        .signing_events
        .iter()
        .enumerate()
        .map(|(i, hash)| {
            let mut target = template.clone();
            target.canonical_event_hash = *hash;
            target.authored_at = certificate.chain_summary.signer_display[i].signed_at;
            target.payload_ref = PayloadRef::Inline(vec![(i + 1) as u8]);
            target
        })
        .collect()
}
struct Proofs {
    same_digest: bool,
    absent: bool,
    malformed: bool,
    no_principal: bool,
}
impl ResponseProofResolver for Proofs {
    fn resolve(&self, bytes: &[u8]) -> Result<Option<CertificateResponseProof>, ResolverError> {
        if self.malformed {
            return Err(ResolverError::MalformedResponseDigest("test".into()));
        }
        if self.absent {
            return Ok(None);
        }
        Ok(Some(CertificateResponseProof {
            response_hash: if bytes[0] == 1 || self.same_digest {
                [0xcc; 32]
            } else {
                [0xdd; 32]
            },
        }))
    }
    fn resolve_principal_ref(&self, bytes: &[u8]) -> Option<String> {
        if self.no_principal {
            None
        } else {
            Some(format!("urn:test:signer:{}", bytes[0]))
        }
    }
}
fn proofs() -> Proofs {
    Proofs {
        same_digest: false,
        absent: false,
        malformed: false,
        no_principal: false,
    }
}
fn finalize(
    certificate: CertificateDetails,
    events: &[EventDetails],
    resolver: &dyn ResponseProofResolver,
    authorities: Option<&CertificateAuthorityRegistry>,
) -> (CertificateOfCompletionOutcome, Vec<VerificationFailure>) {
    let lookup = events
        .iter()
        .enumerate()
        .map(|(i, event)| (event.canonical_event_hash, i))
        .collect();
    let mut failures = vec![];
    let mut outcomes = finalize_certificates_of_completion(
        &[(0, certificate, [3; 32])],
        events,
        &lookup,
        None,
        resolver,
        authorities,
        &mut failures,
    );
    (outcomes.remove(0), failures)
}
fn assert_pass(
    certificate: CertificateDetails,
    events: &[EventDetails],
    resolver: &dyn ResponseProofResolver,
) {
    let (outcome, failures) = finalize(certificate, events, resolver, None);
    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        outcome.all_signing_events_resolved && outcome.chain_summary_consistent,
        "{outcome:?}"
    );
}
#[test]
fn v2_distinct_digests_and_repeated_digest_on_distinct_events_pass() {
    let certificate = decode(&v2_wire(), CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    assert_pass(certificate.clone(), &pool(&certificate), &proofs());
    let mut wire = v2_wire();
    let second = &mut field(field(&mut wire, "chain_summary"), "signer_display")
        .as_array_mut()
        .unwrap()[1];
    set(second, "response_ref", Value::Bytes(vec![0xcc; 32]));
    let certificate = decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    let mut resolver = proofs();
    resolver.same_digest = true;
    assert_pass(certificate.clone(), &pool(&certificate), &resolver);
}
#[test]
fn v2_missing_null_wrong_length_row_digest_and_aggregate_are_rejected() {
    for case in 0..5 {
        let mut wire = v2_wire();
        let summary = field(&mut wire, "chain_summary");
        if case == 4 {
            set(summary, "response_ref", Value::Null);
        } else {
            let first = &mut field(summary, "signer_display").as_array_mut().unwrap()[0];
            match case {
                0 => remove(first, "response_ref"),
                1 => set(first, "response_ref", Value::Null),
                2 => set(first, "response_ref", Value::Bytes(vec![0xcc; 31])),
                _ => set(first, "response_ref", Value::Text("wrong".into())),
            }
        }
        assert!(
            decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn v2_omitted_extra_duplicate_references_and_count_mismatch_are_rejected() {
    for case in 0..4 {
        let mut wire = v2_wire();
        let events = field(&mut wire, "signing_events").as_array_mut().unwrap();
        match case {
            0 => {
                events.pop();
            }
            1 => events.push(Value::Bytes(vec![4; 32])),
            2 => events[1] = events[0].clone(),
            _ => {}
        }
        if case == 3 {
            set(
                field(&mut wire, "chain_summary"),
                "signer_count",
                Value::Integer(1.into()),
            );
        }
        assert_eq!(
            decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION)
                .unwrap_err()
                .kind(),
            Some(VerifyErrorKind::CertificateChainSummaryMismatch)
        );
    }
}
#[test]
fn v2_swapped_or_one_wrong_digest_fails_at_index() {
    for swap in [false, true] {
        let mut wire = v2_wire();
        let rows = field(field(&mut wire, "chain_summary"), "signer_display")
            .as_array_mut()
            .unwrap();
        set(&mut rows[0], "response_ref", Value::Bytes(vec![0xdd; 32]));
        if swap {
            set(&mut rows[1], "response_ref", Value::Bytes(vec![0xcc; 32]));
        }
        let certificate = decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
        let (outcome, failures) =
            finalize(certificate.clone(), &pool(&certificate), &proofs(), None);
        assert!(!outcome.chain_summary_consistent);
        assert!(
            failures
                .iter()
                .any(|f| f.kind == VerificationFailureKind::ResponseRefMismatch)
        );
    }
}
#[test]
fn v2_absent_noop_malformed_unreadable_and_missing_event_fail() {
    let certificate = decode(&v2_wire(), CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    for case in 0..6 {
        let mut events = pool(&certificate);
        let mut resolver = proofs();
        match case {
            0 => resolver.absent = true,
            1 => resolver.malformed = true,
            2 => events[0].payload_ref = PayloadRef::External,
            3 => events[0].payload_ref = PayloadRef::ProtectedExternal,
            4 => {
                events.pop();
            }
            _ => {}
        }
        let selected: &dyn ResponseProofResolver = if case == 5 {
            &NoopResponseProofResolver
        } else {
            &resolver
        };
        let (outcome, failures) = finalize(certificate.clone(), &events, selected, None);
        assert!(!failures.is_empty(), "case {case}");
        assert!(!outcome.chain_summary_consistent || !outcome.all_signing_events_resolved);
    }
}
#[test]
fn v2_missing_wrong_principal_and_wrong_timestamp_fail() {
    let certificate = decode(&v2_wire(), CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    for case in 0..3 {
        let mut events = pool(&certificate);
        let mut resolver = proofs();
        let mut certificate = certificate.clone();
        match case {
            0 => resolver.no_principal = true,
            1 => {
                certificate.chain_summary.signer_display[1].principal_ref = "urn:test:wrong".into()
            }
            _ => events[1].authored_at.nanos += 1,
        }
        let (outcome, failures) = finalize(certificate, &events, &resolver, None);
        assert!(!outcome.chain_summary_consistent, "case {case}");
        assert!(!failures.is_empty());
        if case == 0 {
            // A missing principal leaves the row unresolvable, not "wrong".
            assert!(!outcome.all_signing_events_resolved);
            assert!(outcome.failures.iter().all(|kind| kind == "signing_event_unresolved"));
        }
    }
}
#[test]
fn v1_keeps_none_skips_and_aggregate_any_match() {
    let mut wire = v2_wire();
    let summary = field(&mut wire, "chain_summary");
    set(summary, "response_ref", Value::Bytes(vec![0xcc; 32]));
    for row in field(summary, "signer_display").as_array_mut().unwrap() {
        remove(row, "response_ref");
    }
    let certificate = decode(&wire, CERTIFICATE_EVENT_EXTENSION).unwrap();
    assert_pass(certificate.clone(), &pool(&certificate), &proofs());
    assert_pass(
        certificate.clone(),
        &pool(&certificate),
        &NoopResponseProofResolver,
    );
    let (_, wire) = fixture();
    assert_eq!(
        decode(&wire, CERTIFICATE_EVENT_EXTENSION).unwrap().version,
        CertificateVersion::V1
    );
}
#[test]
fn ambiguous_versions_v2_catalog_and_cross_version_id_collision_are_refused() {
    let wire = v2_wire();
    assert!(
        decode_certificate_payload(&[
            (
                Value::Text(CERTIFICATE_EVENT_EXTENSION.into()),
                wire.clone()
            ),
            (
                Value::Text(CERTIFICATE_V2_EVENT_EXTENSION.into()),
                wire.clone()
            )
        ])
        .is_err()
    );
    let v2 = decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    let mut v1_wire = wire.clone();
    set(
        field(&mut v1_wire, "chain_summary"),
        "response_ref",
        Value::Null,
    );
    let v1 = decode(&v1_wire, CERTIFICATE_EVENT_EXTENSION).unwrap();
    let mut failures = vec![];
    finalize_certificates_of_completion(
        &[(0, v1, [3; 32]), (1, v2.clone(), [4; 32])],
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        None,
        &mut failures,
    );
    assert!(
        failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::CertificateIdCollision)
    );
    let (mut details, _) = fixture();
    details.profile_extensions.insert(
        ProfileExtensionKind::CertificateOfCompletion,
        ProfileExtensionDetails::CertificateOfCompletion(v2.clone()),
    );
    let row = CertificateCatalogEntryRow {
        canonical_event_hash: details.canonical_event_hash,
        certificate_id: v2.certificate_id,
        completed_at: v2.completed_at,
        signer_count: v2.chain_summary.signer_count,
        media_type: v2.presentation_artifact.media_type,
        attachment_id: v2.presentation_artifact.attachment_id,
        workflow_status: v2.chain_summary.workflow_status,
    };
    assert!(!certificate_catalog_row_matches_details(&row, &details));
}
#[test]
fn v2_selected_operator_requires_exact_purpose_with_unchanged_a5_preimage() {
    let mut certificate = decode(&v2_wire(), CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    let mut seed = [0; 32];
    OsSecureRandom.fill_bytes(&mut seed).unwrap();
    let row = &mut certificate.operator_attestations[0];
    row.authority_class = "new".into();
    let bytes = trellis_cddl::certificate_attestation_preimage(
        &certificate.certificate_id,
        certificate.completed_at.seconds,
        certificate.completed_at.nanos,
        &row.authority_class,
    )
    .unwrap();
    row.signature = integrity_cose::sign_ed25519(seed, &bytes).to_vec();
    certificate.operator_attestations.truncate(1);
    let authority = &certificate.operator_attestations[0].authority;
    let mut registry = BTreeMap::from([(
        authority.clone(),
        TrustedCertificateAuthority {
            public_key: ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
            authority_class: "new".into(),
            allowed_purpose: CERTIFICATE_V2_EVENT_EXTENSION.into(),
            valid_from: certificate.completed_at,
            valid_until: certificate.completed_at,
        },
    )]);
    let (outcome, failures) = finalize(
        certificate.clone(),
        &pool(&certificate),
        &proofs(),
        Some(&registry),
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
        outcome.attestation_authority,
        CertificateAttestationAuthorityStatus::Verified
    );
    registry.values_mut().next().unwrap().allowed_purpose = CERTIFICATE_EVENT_EXTENSION.into();
    let (outcome, _) = finalize(
        certificate.clone(),
        &pool(&certificate),
        &proofs(),
        Some(&registry),
    );
    assert_eq!(
        outcome.attestation_authority,
        CertificateAttestationAuthorityStatus::Failed
    );
}
#[test]
fn v2_unknown_claim_status_and_impact_fail_while_v1_preserves_registry_deferral() {
    for (field_name, value, kind) in [
        (
            "covered_claims",
            Value::Array(vec![Value::Text("unknown".into())]),
            VerificationFailureKind::CertificateCoveredClaimUnknown,
        ),
        (
            "workflow_status",
            Value::Text("unknown".into()),
            VerificationFailureKind::CertificateEnumExtensionUnknown,
        ),
        (
            "impact_level",
            Value::Text("unknown".into()),
            VerificationFailureKind::CertificateEnumExtensionUnknown,
        ),
    ] {
        let mut wire = v2_wire();
        set(field(&mut wire, "chain_summary"), field_name, value);
        let v2 = decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
        let (outcome, failures) = finalize(v2.clone(), &pool(&v2), &proofs(), None);
        assert!(!outcome.chain_summary_consistent);
        assert!(failures.iter().any(|f| f.kind == kind));
        let v1 = decode(&wire, CERTIFICATE_EVENT_EXTENSION).unwrap();
        assert_pass(v1.clone(), &pool(&v1), &proofs());
    }
}

#[test]
fn v2_duplicate_extension_and_complete_same_version_payload_collision_fail() {
    let wire = v2_wire();
    assert!(
        decode_certificate_payload(&[
            (
                Value::Text(CERTIFICATE_V2_EVENT_EXTENSION.into()),
                wire.clone()
            ),
            (
                Value::Text(CERTIFICATE_V2_EVENT_EXTENSION.into()),
                wire.clone()
            ),
        ])
        .is_err()
    );
    let first = decode(&wire, CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    let mut changed = wire;
    let row = &mut field(field(&mut changed, "chain_summary"), "signer_display")
        .as_array_mut()
        .unwrap()[0];
    set(
        row,
        "display_name",
        Value::Text("Different display name".into()),
    );
    let second = decode(&changed, CERTIFICATE_V2_EVENT_EXTENSION).unwrap();
    let mut failures = vec![];
    finalize_certificates_of_completion(
        &[(0, first, [3; 32]), (1, second, [4; 32])],
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        None,
        &mut failures,
    );
    assert!(
        failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::CertificateIdCollision)
    );
}

#[test]
fn v2_extension_requires_matching_event_type() {
    let event = parse_sign1_bytes(include_bytes!(
        "../../tests/fixtures/native-external/certificate-event.cbor"
    ))
    .unwrap();
    let mut payload = decode_value(event.payload.as_ref().unwrap()).unwrap();
    let extensions = field(&mut payload, "extensions");
    remove(extensions, CERTIFICATE_EVENT_EXTENSION);
    set(extensions, CERTIFICATE_V2_EVENT_EXTENSION, v2_wire());
    let mut event = event;
    event.payload = Some(trellis_types::encode_canonical_cbor_value(&payload).unwrap());
    assert!(decode_event_details(&event).is_err());
    set(
        field(&mut payload, "header"),
        "event_type",
        Value::Bytes(CERTIFICATE_V2_EVENT_EXTENSION.as_bytes().to_vec()),
    );
    event.payload = Some(trellis_types::encode_canonical_cbor_value(&payload).unwrap());
    assert_eq!(
        decode_event_details(&event)
            .unwrap()
            .certificate()
            .unwrap()
            .version,
        CertificateVersion::V2
    );
}

#[test]
fn v2_event_type_rejects_v1_only_missing_null_empty_and_ambiguous_extensions() {
    for case in 0..6 {
        let mut event = parse_sign1_bytes(include_bytes!(
            "../../tests/fixtures/native-external/certificate-event.cbor"
        ))
        .unwrap();
        let mut payload = decode_value(event.payload.as_ref().unwrap()).unwrap();
        set(
            field(&mut payload, "header"),
            "event_type",
            Value::Bytes(CERTIFICATE_V2_EVENT_EXTENSION.as_bytes().to_vec()),
        );
        match case {
            0 => {} // V1 only: must not inherit V1 proof skips or aggregate any-match.
            1 => remove(&mut payload, "extensions"),
            2 => set(&mut payload, "extensions", Value::Null),
            3 => set(&mut payload, "extensions", Value::Map(vec![])),
            4 => set(
                field(&mut payload, "extensions"),
                CERTIFICATE_V2_EVENT_EXTENSION,
                v2_wire(),
            ),
            _ => {
                remove(
                    field(&mut payload, "extensions"),
                    CERTIFICATE_EVENT_EXTENSION,
                );
                field(&mut payload, "extensions")
                    .as_map_mut()
                    .unwrap()
                    .extend([
                        (
                            Value::Text(CERTIFICATE_V2_EVENT_EXTENSION.into()),
                            v2_wire(),
                        ),
                        (
                            Value::Text(CERTIFICATE_V2_EVENT_EXTENSION.into()),
                            v2_wire(),
                        ),
                    ]);
            }
        }
        let mut bytes = vec![];
        // Serialize the malicious duplicate map without the producer's canonical guard.
        ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
        event.payload = Some(bytes);
        assert!(decode_event_details(&event).is_err(), "case {case}");
    }
}
