// Rust guideline compliant 2026-02-21
//! End-to-end tests for the universal verifier.

use ed25519_dalek::{Signer, SigningKey};
use integrity_cose::{protected_header_bytes, sig_structure_bytes, sign1_bytes};

use crate::{
    BundleEntryView, CanonicalDigestCheck, ChainEventView, ProfileRegistry,
    ProfileVerificationResult, ProfileVerifier, SubstrateTier, UniversalFailureKind,
    VerifyBundleInput, VerifyEvent, verify_universal,
};

struct AlwaysOk(&'static str);
impl ProfileVerifier for AlwaysOk {
    fn verifier_id(&self) -> &str {
        self.0
    }
    fn verify_profile_record(&self, _: &[u8], _: &[u8]) -> ProfileVerificationResult {
        ProfileVerificationResult::verified(self.verifier_id(), "always-ok")
    }
}

struct AlwaysFail(&'static str);
impl ProfileVerifier for AlwaysFail {
    fn verifier_id(&self) -> &str {
        self.0
    }
    fn verify_profile_record(&self, _: &[u8], _: &[u8]) -> ProfileVerificationResult {
        ProfileVerificationResult::failed(self.verifier_id(), "always-fail", vec!["nope".into()])
    }
}

fn build_signed_event(seed: [u8; 32], payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let protected = protected_header_bytes([0xab; 16]);
    let sig_struct = sig_structure_bytes(&protected, payload);
    let signature: ed25519_dalek::Signature = signing_key.sign(&sig_struct);
    let bytes = sign1_bytes(&protected, payload, signature.to_bytes());
    (bytes, public_key)
}

fn build_retired_profile_event(seed: [u8; 32], payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let protected = vec![
        0xa4, 0x01, 0x27, 0x04, 0x50, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x3a, 0x00, 0x01,
        0x00, 0x02, 0x18, 0x63,
    ];
    let sig_struct = sig_structure_bytes(&protected, payload);
    let signature: ed25519_dalek::Signature = signing_key.sign(&sig_struct);
    let bytes = sign1_bytes(&protected, payload, signature.to_bytes());
    (bytes, public_key)
}

#[test]
fn verify_universal_accepts_well_formed_event_with_default_profile() {
    let (event_bytes, public_key) = build_signed_event([0x01; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(report.universal_verified, "{report:?}");
    assert!(report.profile_verified, "{report:?}");
    assert_eq!(report.profile_results.len(), 1);
}

#[test]
fn verify_universal_rejects_retired_profile_header_as_malformed() {
    let (event_bytes, public_key) = build_retired_profile_event([0x02; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let registry = ProfileRegistry::new();

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(
        report
            .universal_failures
            .iter()
            .any(|f| f.kind == UniversalFailureKind::MalformedEnvelope
                && f.message.contains("RetiredProfileIdPresent")),
        "expected retired profile header to be malformed, got {report:?}"
    );
}

#[test]
fn verify_universal_routes_to_default_profile_verifier() {
    let (event_bytes, public_key) = build_signed_event([0x03; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysFail("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(!report.profile_verified);
    assert_eq!(report.profile_results.len(), 1);
    assert_eq!(report.profile_results[0].verdict, "always-fail");
    assert_eq!(report.profile_results[0].verifier_id, "default");
}

#[test]
fn verify_universal_detects_bad_signature() {
    let (event_bytes, _) = build_signed_event([0x04; 32], b"payload");
    let wrong_key = [0u8; 32];
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(wrong_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(
        report
            .universal_failures
            .iter()
            .any(|f| f.kind == UniversalFailureKind::SignatureInvalid),
        "expected SignatureInvalid, got {report:?}"
    );
}

#[test]
fn verify_universal_runs_bundle_and_chain_checks() {
    let entries = [
        BundleEntryView { path: "a/x" },
        BundleEntryView { path: "a/y" },
    ];
    let h0 = [0x10; 32];
    let h1 = [0x20; 32];
    let chain = [
        ChainEventView {
            sequence: 0,
            canonical_event_hash: h0,
            previous_hash: None,
        },
        ChainEventView {
            sequence: 1,
            canonical_event_hash: h1,
            previous_hash: Some(h0),
        },
    ];
    let registry = ProfileRegistry::new();
    let report = verify_universal(
        &VerifyBundleInput {
            events: &[],
            bundle_entries: Some(&entries),
            chain_events: Some(&chain),
            canonical_digest_check: None,
        },
        &registry,
    );
    assert!(report.bundle_checked);
    assert!(report.chain_checked);
    assert!(report.bundle_findings.is_empty());
    assert!(report.chain_findings.is_empty());
    assert!(report.universal_verified);
    assert_eq!(report.substrate_tier, None);
}

#[test]
fn verify_universal_runs_canonical_digest_check() {
    use integrity_canonical::{DigestAlgorithm, compute_digest};
    let bytes = b"canonical body";
    let digest = compute_digest(bytes, DigestAlgorithm::Sha256);
    let check = CanonicalDigestCheck {
        bytes,
        algorithm_token: "sha-256",
        declared_digest: &digest,
    };
    let registry = ProfileRegistry::new();
    let report = verify_universal(
        &VerifyBundleInput {
            events: &[],
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: Some(&check),
        },
        &registry,
    );
    assert!(report.canonical_checked);
    assert!(report.canonical_findings.is_empty());
    assert!(report.universal_verified);
}

// ---- 3C.2 substrate_tier tests --------------------------------------------

#[test]
fn substrate_tier_l0_when_only_envelope_verified() {
    let (event_bytes, public_key) = build_signed_event([0xa0; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(report.universal_verified, "{report:?}");
    assert_eq!(report.substrate_tier, Some(SubstrateTier::L0));
}

#[test]
fn substrate_tier_l1_when_chain_continuity_verified() {
    let (event_bytes, public_key) = build_signed_event([0xa1; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let chain = [
        ChainEventView {
            sequence: 0,
            canonical_event_hash: [0x10; 32],
            previous_hash: None,
        },
        ChainEventView {
            sequence: 1,
            canonical_event_hash: [0x20; 32],
            previous_hash: Some([0x10; 32]),
        },
    ];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: Some(&chain),
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(report.universal_verified, "{report:?}");
    assert_eq!(report.substrate_tier, Some(SubstrateTier::L1));
}

#[test]
fn substrate_tier_l2_when_chain_and_bundle_verified() {
    let (event_bytes, public_key) = build_signed_event([0xa2; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let chain = [
        ChainEventView {
            sequence: 0,
            canonical_event_hash: [0x10; 32],
            previous_hash: None,
        },
        ChainEventView {
            sequence: 1,
            canonical_event_hash: [0x20; 32],
            previous_hash: Some([0x10; 32]),
        },
    ];
    let entries = [
        BundleEntryView { path: "a/x" },
        BundleEntryView { path: "a/y" },
    ];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: Some(&entries),
            chain_events: Some(&chain),
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(report.universal_verified, "{report:?}");
    assert_eq!(report.substrate_tier, Some(SubstrateTier::L2));
}

#[test]
fn substrate_tier_drops_when_chain_continuity_violated() {
    let (event_bytes, public_key) = build_signed_event([0xa3; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    // Sequence-1 event declares a wrong prev_hash → chain finding.
    let chain = [
        ChainEventView {
            sequence: 0,
            canonical_event_hash: [0x10; 32],
            previous_hash: None,
        },
        ChainEventView {
            sequence: 1,
            canonical_event_hash: [0x20; 32],
            previous_hash: Some([0xff; 32]),
        },
    ];
    let entries = [
        BundleEntryView { path: "a/x" },
        BundleEntryView { path: "a/y" },
    ];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: Some(&entries),
            chain_events: Some(&chain),
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(
        !report.chain_findings.is_empty(),
        "expected a chain-continuity finding, got {report:?}"
    );
    // Failure at the chain layer drops the tier below L1: envelope-level
    // verification still passed, so L0 remains attestable, but L1/L2
    // (which require chain continuity) do not. Bundle structural pass
    // alone cannot lift the tier past the broken chain rung.
    assert_eq!(report.substrate_tier, Some(SubstrateTier::L0));
    assert!(!report.universal_verified);
}

#[test]
fn substrate_tier_none_for_vacuous_input() {
    let registry = ProfileRegistry::new();
    let report = verify_universal(
        &VerifyBundleInput {
            events: &[],
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );
    assert_eq!(report.substrate_tier, None);
}

#[test]
fn substrate_tier_string_tokens_are_stable() {
    assert_eq!(SubstrateTier::L0.as_str(), "L0");
    assert_eq!(SubstrateTier::L1.as_str(), "L1");
    assert_eq!(SubstrateTier::L2.as_str(), "L2");
    assert_eq!(SubstrateTier::L3.as_str(), "L3");
}

// ---- default semantic verifier dispatch tests ------------------------------

#[test]
fn default_verifier_handles_post_adr_0109_envelopes() {
    let (event_bytes, public_key) = build_signed_event([0xb0; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysOk("wos-default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    assert!(report.profile_verified, "{report:?}");
    assert_eq!(report.profile_results.len(), 1);
    assert_eq!(report.profile_results[0].verifier_id, "wos-default");
    assert!(
        report
            .universal_failures
            .iter()
            .all(|f| f.kind != UniversalFailureKind::MissingProfileVerifier),
        "expected no missing-verifier failures, got {report:?}"
    );
}

#[test]
fn retired_profile_header_surfaces_as_malformed_envelope() {
    let (event_bytes, public_key) = build_retired_profile_event([0xb1; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysOk("default")));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    let malformed = report
        .universal_failures
        .iter()
        .find(|f| f.kind == UniversalFailureKind::MalformedEnvelope)
        .expect("expected MalformedEnvelope failure in report");
    assert!(
        malformed.message.contains("RetiredProfileIdPresent"),
        "expected diagnostic to name retired label, got: {}",
        malformed.message
    );
}

#[test]
fn missing_default_verifier_surfaces_in_report() {
    let (event_bytes, public_key) = build_signed_event([0xb2; 32], b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let registry = ProfileRegistry::new();

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    let missing = report
        .universal_failures
        .iter()
        .find(|f| f.kind == UniversalFailureKind::MissingProfileVerifier)
        .expect("expected MissingProfileVerifier failure in report");
    assert!(
        missing.message.contains("no default ProfileVerifier"),
        "expected diagnostic to name missing verifier, got: {}",
        missing.message
    );
    assert!(!report.universal_verified, "{report:?}");
    assert_eq!(report.profile_results.len(), 0);
    assert_eq!(report.substrate_tier, None);
}

#[test]
fn default_verifier_lookup_returns_registered_verifier() {
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysOk("default")));

    let known = registry
        .lookup_required()
        .expect("default verifier should route");
    assert_eq!(known.verifier_id(), "default");
}

#[test]
fn missing_default_verifier_returns_named_error() {
    let registry = ProfileRegistry::new();
    let err = registry
        .lookup_required()
        .err()
        .expect("expected MissingDefaultVerifier error");
    assert_eq!(err, crate::ProfileDispatchError::MissingDefaultVerifier);
}
