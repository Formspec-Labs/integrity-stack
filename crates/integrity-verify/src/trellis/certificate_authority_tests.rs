// Rust guideline compliant 2026-02-21
//! Explicit certificate authority checks with distinct fresh test event/operator keys.

use super::parse::{decode_event_details, decode_value};
use super::*;
use ciborium::Value;
use integrity_seam::{OsSecureRandom, SecureRandom};
use trellis_types::encode_canonical_cbor_value;

struct Trust(CertificateAuthorityRegistry);
impl RecordValidator for Trust {
    fn certificate_authority_registry(&self) -> Option<&CertificateAuthorityRegistry> {
        Some(&self.0)
    }
}
fn fresh_seed() -> [u8; 32] {
    let mut seed = [0; 32];
    OsSecureRandom.fill_bytes(&mut seed).unwrap();
    seed
}
fn field<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
    v.as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap()
}
fn signed_event(mut event: ParsedSign1, value: &mut Value, seed: [u8; 32]) -> Vec<u8> {
    let provisional = encode_canonical_cbor_value(value).unwrap();
    let hash = super::merkle::recompute_author_event_hash(&provisional).unwrap();
    *field(value, "author_event_hash") = Value::Bytes(hash.to_vec());
    let payload = encode_canonical_cbor_value(value).unwrap();
    event.signature =
        integrity_cose::sign_ed25519(seed, &sig_structure_bytes(&event.protected_bytes, &payload));
    integrity_cose::sign1_bytes(&event.protected_bytes, &payload, event.signature)
}
fn prepared() -> (ParsedSign1, Value, [u8; 32], Trust) {
    let event = parse_sign1_bytes(include_bytes!(
        "../../tests/fixtures/native-external/certificate-event.cbor"
    ))
    .unwrap();
    let details = decode_event_details(&event).unwrap();
    let cert = details.certificate().unwrap();
    let event_seed = fresh_seed();
    let operator_seed = fresh_seed();
    assert_ne!(event_seed, operator_seed);
    let preimage = trellis_cddl::certificate_attestation_preimage(
        &cert.certificate_id,
        cert.completed_at.seconds,
        cert.completed_at.nanos,
        "new",
    )
    .unwrap();
    let signature = integrity_cose::sign_ed25519(operator_seed, &preimage);
    let mut value = decode_value(event.payload.as_ref().unwrap()).unwrap();
    let certificate = field(
        field(&mut value, "extensions"),
        "trellis.certificate-of-completion.v1",
    );
    *field(certificate, "attestations") = Value::Array(vec![Value::Map(vec![
        (
            Value::Text("authority".into()),
            Value::Text("urn:development:fictional:test-completion".into()),
        ),
        (
            Value::Text("authority_class".into()),
            Value::Text("new".into()),
        ),
        (
            Value::Text("signature".into()),
            Value::Bytes(signature.to_vec()),
        ),
    ])]);
    let trust = Trust(BTreeMap::from([(
        "urn:development:fictional:test-completion".into(),
        TrustedCertificateAuthority {
            public_key: ed25519_dalek::SigningKey::from_bytes(&operator_seed)
                .verifying_key()
                .to_bytes(),
            authority_class: "new".into(),
            allowed_purpose: CERTIFICATE_EVENT_EXTENSION.into(),
            valid_from: cert.completed_at,
            valid_until: cert.completed_at,
        },
    )]));
    (event, value, event_seed, trust)
}
fn check(
    event: ParsedSign1,
    mut value: Value,
    seed: [u8; 32],
    validator: &dyn RecordValidator,
) -> VerificationReport {
    let signed = signed_event(event, &mut value, seed);
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    verify_single_event_with_validator(public, &signed, validator)
        .unwrap()
        .trellis
}
#[test]
fn selected_operator_registry_verifies_separate_keys_and_default_is_explicitly_unchecked() {
    let (event, value, seed, trust) = prepared();
    let report = check(event.clone(), value.clone(), seed, &trust);
    assert!(
        !report
            .event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::AttestationInsufficient),
        "{report:?}"
    );
    assert_eq!(
        report.certificates_of_completion[0].attestation_authority,
        CertificateAttestationAuthorityStatus::Verified
    );
    let report = check(event, value, seed, &());
    assert!(!report.integrity_verified);
    assert!(
        report
            .event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::SigningEventUnresolved)
    );
    assert_eq!(
        report.certificates_of_completion[0].attestation_authority,
        CertificateAttestationAuthorityStatus::Unchecked
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|s| s.contains("authority is unchecked"))
    );
}
#[test]
fn selected_trust_refuses_unknown_uri_wrong_class_key_purpose_or_time() {
    for case in 0..7 {
        let (event, value, seed, mut trust) = prepared();
        if case == 0 {
            trust.0.clear();
        } else {
            let key = trust.0.values_mut().next().unwrap();
            match case {
                1 => key.authority_class = "prior".into(),
                2 => {
                    key.public_key = ed25519_dalek::SigningKey::from_bytes(&fresh_seed())
                        .verifying_key()
                        .to_bytes()
                }
                3 => key.allowed_purpose = "trellis.posture-transition.v1".into(),
                4 => {
                    key.valid_from.seconds -= 2;
                    key.valid_until.seconds -= 1;
                }
                5 => key.valid_from.nanos = 1_000_000_000,
                6 => {
                    key.valid_from.seconds += 1;
                    key.valid_until.seconds += 2;
                }
                _ => unreachable!(),
            }
        }
        let report = check(event, value, seed, &trust);
        assert!(!report.integrity_verified, "case{case}: {report:?}");
        assert_eq!(
            report.certificates_of_completion[0].attestation_authority,
            CertificateAttestationAuthorityStatus::Failed
        );
        assert!(
            report
                .event_failures
                .iter()
                .any(|f| f.kind == VerificationFailureKind::AttestationInsufficient)
        );
        assert!(
            !report
                .event_failures
                .iter()
                .any(|f| f.kind == VerificationFailureKind::SignatureInvalid)
        );
    }
}
#[test]
fn valid_event_signature_does_not_hide_modified_operator_signature_or_completion_time() {
    for change_time in [false, true] {
        let (event, mut value, seed, mut trust) = prepared();
        let cert = field(
            field(&mut value, "extensions"),
            "trellis.certificate-of-completion.v1",
        );
        if change_time {
            let timestamp = field(cert, "completed_at").as_array_mut().unwrap();
            timestamp[1] = Value::Integer(1.into());
            trust.0.values_mut().next().unwrap().valid_until.nanos = 2;
        } else {
            let row = &mut field(cert, "attestations").as_array_mut().unwrap()[0];
            field(row, "signature").as_bytes_mut().unwrap()[0] ^= 1;
        }
        let report = check(event, value, seed, &trust);
        assert!(!report.integrity_verified);
        assert_eq!(
            report.certificates_of_completion[0].attestation_authority,
            CertificateAttestationAuthorityStatus::Failed
        );
        assert!(
            !report
                .event_failures
                .iter()
                .any(|f| f.kind == VerificationFailureKind::SignatureInvalid)
        );
    }
}
