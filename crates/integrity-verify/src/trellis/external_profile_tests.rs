// Rust guideline compliant 2026-02-21
//! Generic verifier admission of the native protected profile; no recipient authority claim.

use super::parse::{decode_event_details, decode_value, readable_payload_bytes};
use super::validator::{DomainEvent, DomainFinding};
use super::*;
use ciborium::Value;
use std::cell::RefCell;
use trellis_types::encode_canonical_cbor_value;

const EVENT: &[u8] = include_bytes!("../../tests/fixtures/native-external/expected-event.cbor");
const BODY: &[u8] =
    include_bytes!("../../tests/fixtures/native-external/input-attachment-ciphertext.bin");

fn signing_seed() -> [u8; 32] {
    let key = decode_value(include_bytes!(
        "../../tests/fixtures/native-external/issuer-001.cose_key"
    ))
    .unwrap();
    key.as_map()
        .unwrap()
        .iter()
        .find_map(|(k, v)| {
            (k.as_integer().and_then(|v| i128::try_from(v).ok()) == Some(-4))
                .then(|| v.as_bytes().unwrap().as_slice().try_into().unwrap())
        })
        .unwrap()
}
fn event() -> ParsedSign1 {
    parse_sign1_bytes(EVENT).unwrap()
}
fn registry(event: &ParsedSign1) -> BTreeMap<Vec<u8>, SigningKeyEntry> {
    let key = ed25519_dalek::SigningKey::from_bytes(&signing_seed());
    BTreeMap::from([(
        event.kid.clone(),
        SigningKeyEntry {
            public_key: key.verifying_key().to_bytes(),
            status: 0,
            valid_from: None,
            valid_to: None,
        },
    )])
}
fn field_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
    v.as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap()
}
fn resign(mut event: ParsedSign1, value: &Value) -> ParsedSign1 {
    let bytes = encode_canonical_cbor_value(value).unwrap();
    event.signature = integrity_cose::sign_ed25519(
        signing_seed(),
        &sig_structure_bytes(&event.protected_bytes, &bytes),
    );
    event.payload = Some(bytes);
    event
}
#[derive(Default)]
struct Capture(RefCell<Vec<DomainEvent>>);
impl RecordValidator for Capture {
    fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
        self.0.replace(events.to_vec());
        Vec::new()
    }
}
#[test]
fn native_external_profile_verifies_ciphertext_without_claiming_original_readability() {
    let event = event();
    let details = decode_event_details(&event).unwrap();
    assert!(matches!(details.payload_ref, PayloadRef::ProtectedExternal));
    let blobs = BTreeMap::from([(details.content_hash, BODY.to_vec())]);
    assert!(readable_payload_bytes(&details, &blobs).is_none());
    let capture = Capture::default();
    let result = verify_event_set_with_domain(
        &[event.clone()],
        &registry(&event),
        None,
        None,
        false,
        None,
        Some(&blobs),
        &capture,
    );
    assert!(result.trellis.integrity_verified, "{:?}", result.trellis);
    assert!(!result.trellis.readability_verified);
    assert!(
        result
            .trellis
            .warnings
            .iter()
            .any(|s| s.contains("recipient permission"))
    );
    assert_eq!(capture.0.borrow().len(), 1);
    assert!(capture.0.borrow()[0].payload.is_none());
    let mut wrong = blobs;
    wrong.get_mut(&details.content_hash).unwrap()[0] ^= 1;
    let result = verify_event_set(
        &[event.clone()],
        &registry(&event),
        None,
        None,
        false,
        None,
        Some(&wrong),
    );
    assert!(!result.integrity_verified);
    assert!(
        result
            .event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ContentHashMismatch)
    );
}
#[test]
fn signed_unknown_wrong_shape_or_inline_profile_is_refused_before_readable_decode() {
    for marker in [
        Value::Text("unknown".into()),
        Value::Bytes(b"trellis.external-attachment-suite1.v1".to_vec()),
    ] {
        let event = event();
        let mut value = decode_value(event.payload.as_ref().unwrap()).unwrap();
        *field_mut(
            field_mut(&mut value, "extensions"),
            "trellis.payload-protection-profile.v1",
        ) = marker;
        let event = resign(event, &value);
        assert!(verify_signature(
            &event,
            registry(&event)[&event.kid].public_key
        ));
        assert!(decode_event_details(&event).is_err());
        let result = verify_event_set(
            &[event.clone()],
            &registry(&event),
            None,
            None,
            false,
            None,
            None,
        );
        assert!(!result.structure_verified);
        assert!(!result.integrity_verified);
    }
    let event = event();
    let mut value = decode_value(event.payload.as_ref().unwrap()).unwrap();
    *field_mut(field_mut(&mut value, "payload_ref"), "ref_type") = Value::Text("inline".into());
    assert!(decode_event_details(&resign(event, &value)).is_err());
    let event = self::event();
    let mut value = decode_value(event.payload.as_ref().unwrap()).unwrap();
    field_mut(&mut value, "extensions")
        .as_map_mut()
        .unwrap()
        .retain(|(k, _)| k.as_text() != Some("trellis.evidence-attachment-binding.v1"));
    assert!(decode_event_details(&resign(event, &value)).is_err());
}
#[test]
fn selected_profile_requires_matching_reference_hash_and_nonempty_real_key_bag() {
    let event = event();
    let original = decode_value(event.payload.as_ref().unwrap()).unwrap();
    let mut value = original.clone();
    *field_mut(field_mut(&mut value, "payload_ref"), "content_hash") = Value::Bytes(vec![0; 32]);
    assert!(decode_event_details(&resign(event.clone(), &value)).is_err());
    let mut value = original;
    *field_mut(field_mut(&mut value, "key_bag"), "entries") = Value::Array(Vec::new());
    assert!(decode_event_details(&resign(event, &value)).is_err());
}

#[test]
fn profile_without_valid_signature_cannot_be_admitted() {
    let mut event = event();
    event.signature[0] ^= 1;
    let result = verify_event_set(
        &[event.clone()],
        &registry(&event),
        None,
        None,
        false,
        None,
        None,
    );
    assert!(!result.integrity_verified);
    assert!(
        result
            .event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::SignatureInvalid)
    );
}
#[test]
fn marker_absence_preserves_existing_generic_external_interpretation() {
    let event = event();
    let mut value = decode_value(event.payload.as_ref().unwrap()).unwrap();
    field_mut(&mut value, "extensions")
        .as_map_mut()
        .unwrap()
        .retain(|(k, _)| k.as_text() != Some("trellis.payload-protection-profile.v1"));
    let event = resign(event, &value);
    let details = decode_event_details(&event).unwrap();
    assert!(matches!(details.payload_ref, PayloadRef::External));
    let blobs = BTreeMap::from([(details.content_hash, BODY.to_vec())]);
    assert_eq!(readable_payload_bytes(&details, &blobs).unwrap(), BODY);
}

#[test]
fn certificate_cannot_resolve_protected_presentation_from_matching_ciphertext_digest() {
    let binding_event = event();
    let binding_details = decode_event_details(&binding_event).unwrap();
    let binding = binding_details.attachment_binding().unwrap();
    let certificate_event = parse_sign1_bytes(include_bytes!(
        "../../tests/fixtures/native-external/certificate-event.cbor"
    ))
    .unwrap();
    let mut value = decode_value(certificate_event.payload.as_ref().unwrap()).unwrap();
    let cert = field_mut(
        field_mut(&mut value, "extensions"),
        "trellis.certificate-of-completion.v1",
    );
    let presentation = field_mut(cert, "presentation_artifact");
    *field_mut(presentation, "attachment_id") = Value::Text(binding.attachment_id.clone());
    *field_mut(presentation, "content_hash") =
        Value::Bytes(domain_separated_sha256(PRESENTATION_ARTIFACT_DOMAIN, BODY).to_vec());
    let certificate_event = resign(certificate_event, &value);
    let cert_details = decode_event_details(&certificate_event).unwrap();
    let cert = cert_details.certificate().unwrap();
    let outcome = CertificateOfCompletionOutcome {
        attestation_authority: CertificateAttestationAuthorityStatus::Unchecked,
        certificate_id: cert.certificate_id.clone(),
        event_index: 1,
        completed_at: cert.completed_at,
        signer_count: cert.chain_summary.signer_count,
        attachment_resolved: true,
        all_signing_events_resolved: true,
        chain_summary_consistent: true,
        failures: Vec::new(),
    };
    let mut report = VerificationReport::from_integrity_state(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![outcome],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let blobs = BTreeMap::from([(binding_details.content_hash, BODY.to_vec())]);
    super::certificate::verify_certificate_attachment_lineage(
        &[binding_event, certificate_event],
        &blobs,
        &mut report,
    );
    assert!(!report.certificates_of_completion[0].attachment_resolved);
    assert!(
        report
            .event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::PresentationArtifactAttachmentMissing)
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|s| s.contains("protected presentation original is unchecked"))
    );
}
