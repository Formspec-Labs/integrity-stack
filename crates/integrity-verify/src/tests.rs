// Rust guideline compliant 2026-02-21
//! End-to-end tests for the universal verifier.

use ed25519_dalek::{Signer, SigningKey};
use integrity_cose::{
    protected_header_bytes, protected_header_bytes_with_profile_id, sig_structure_bytes,
    sign1_bytes,
};

use crate::{
    BundleEntryView, CanonicalDigestCheck, ChainEventView, ProfileDispatchError, ProfileRegistry,
    ProfileVerificationResult, ProfileVerifier, SubstrateTier, UniversalFailureKind,
    VerifyBundleInput, VerifyEvent, WOS_PROFILE_ID, verify_universal,
};

struct AlwaysOk(u64);
impl ProfileVerifier for AlwaysOk {
    fn profile_id(&self) -> u64 {
        self.0
    }
    fn verify_profile_record(
        &self,
        envelope_profile_id: u64,
        _: &[u8],
        _: &[u8],
    ) -> ProfileVerificationResult {
        ProfileVerificationResult::verified(envelope_profile_id, "always-ok")
    }
}

struct AlwaysFail(u64);
impl ProfileVerifier for AlwaysFail {
    fn profile_id(&self) -> u64 {
        self.0
    }
    fn verify_profile_record(
        &self,
        envelope_profile_id: u64,
        _: &[u8],
        _: &[u8],
    ) -> ProfileVerificationResult {
        ProfileVerificationResult::failed(envelope_profile_id, "always-fail", vec!["nope".into()])
    }
}

fn build_signed_event(
    seed: [u8; 32],
    profile_id: Option<u64>,
    payload: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let protected = match profile_id {
        Some(id) => protected_header_bytes_with_profile_id([0xab; 16], id),
        None => protected_header_bytes([0xab; 16]),
    };
    let sig_struct = sig_structure_bytes(&protected, payload);
    let signature: ed25519_dalek::Signature = signing_key.sign(&sig_struct);
    let bytes = sign1_bytes(&protected, payload, signature.to_bytes());
    (bytes, public_key)
}

#[test]
fn verify_universal_accepts_well_formed_event_with_default_profile() {
    let (event_bytes, public_key) = build_signed_event([0x01; 32], None, b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk(0)));

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
fn verify_universal_rejects_unknown_profile_id() {
    let (event_bytes, public_key) = build_signed_event([0x02; 32], Some(99), b"payload");
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
            .any(|f| f.kind == UniversalFailureKind::UnknownProfileId),
        "expected UnknownProfileId failure, got {report:?}"
    );
}

#[test]
fn verify_universal_routes_to_registered_profile() {
    let (event_bytes, public_key) = build_signed_event([0x03; 32], Some(7), b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysFail(7)));

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
    assert_eq!(report.profile_results[0].profile_id, 7);
}

#[test]
fn verify_universal_detects_bad_signature() {
    let (event_bytes, _) = build_signed_event([0x04; 32], None, b"payload");
    let wrong_key = [0u8; 32];
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(wrong_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk(0)));

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
    let (event_bytes, public_key) = build_signed_event([0xa0; 32], None, b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register_default(Box::new(AlwaysOk(0)));

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
    let (event_bytes, public_key) = build_signed_event([0xa1; 32], None, b"payload");
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
    registry.register_default(Box::new(AlwaysOk(0)));

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
    let (event_bytes, public_key) = build_signed_event([0xa2; 32], None, b"payload");
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
    registry.register_default(Box::new(AlwaysOk(0)));

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
    let (event_bytes, public_key) = build_signed_event([0xa3; 32], None, b"payload");
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
    registry.register_default(Box::new(AlwaysOk(0)));

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

// ---- 3C.3 explicit profile dispatch tests ---------------------------------

#[test]
fn wos_profile_id_routes_to_registered_verifier() {
    let (event_bytes, public_key) =
        build_signed_event([0xb0; 32], Some(WOS_PROFILE_ID), b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysOk(WOS_PROFILE_ID)));

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
    assert_eq!(report.profile_results[0].profile_id, WOS_PROFILE_ID);
    assert!(
        report
            .universal_failures
            .iter()
            .all(|f| f.kind != UniversalFailureKind::UnknownProfileId),
        "expected no UnknownProfileId failures, got {report:?}"
    );
}

#[test]
fn unknown_profile_id_rejects_with_named_error() {
    let registry = ProfileRegistry::new();
    let err = registry
        .lookup_required(Some(9999))
        .err()
        .expect("expected UnknownProfileId error");
    assert_eq!(err, ProfileDispatchError::UnknownProfileId(9999));
    assert!(err.to_string().contains("9999"));
}

#[test]
fn unknown_profile_id_surfaces_in_report() {
    let (event_bytes, public_key) = build_signed_event([0xb1; 32], Some(9999), b"payload");
    let events = [VerifyEvent {
        sign1_bytes: &event_bytes,
        public_key: Some(public_key),
        detached_payload: None,
    }];
    let mut registry = ProfileRegistry::new();
    // Register a different profile so the registry is non-empty.
    registry.register(Box::new(AlwaysOk(WOS_PROFILE_ID)));

    let report = verify_universal(
        &VerifyBundleInput {
            events: &events,
            bundle_entries: None,
            chain_events: None,
            canonical_digest_check: None,
        },
        &registry,
    );

    let unknown = report
        .universal_failures
        .iter()
        .find(|f| f.kind == UniversalFailureKind::UnknownProfileId)
        .expect("expected UnknownProfileId failure in report");
    assert!(
        unknown.message.contains("9999"),
        "expected diagnostic to name the rejected profile_id, got: {}",
        unknown.message
    );
}

#[test]
fn missing_profile_id_without_default_surfaces_in_report() {
    let (event_bytes, public_key) = build_signed_event([0xb2; 32], None, b"payload");
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
        .find(|f| f.kind == UniversalFailureKind::MissingProfileIdNoDefault)
        .expect("expected MissingProfileIdNoDefault failure in report");
    assert!(
        missing.message.contains("no profile_id"),
        "expected diagnostic to name missing profile_id, got: {}",
        missing.message
    );
    assert!(!report.universal_verified, "{report:?}");
    assert_eq!(report.profile_results.len(), 0);
    assert_eq!(report.substrate_tier, None);
}

#[test]
fn wos_profile_id_round_trip_dispatch_and_named_rejection() {
    // Round trip: same registry serves a known profile id and rejects an
    // unknown one with a named error.
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AlwaysOk(WOS_PROFILE_ID)));

    let known = registry
        .lookup_required(Some(WOS_PROFILE_ID))
        .expect("WOS_PROFILE_ID should route to registered verifier");
    assert_eq!(known.profile_id(), WOS_PROFILE_ID);

    let unknown = registry.lookup_required(Some(9999));
    assert_eq!(
        unknown.err(),
        Some(ProfileDispatchError::UnknownProfileId(9999))
    );
}

#[test]
fn missing_profile_id_with_no_default_returns_named_error() {
    let registry = ProfileRegistry::new();
    let err = registry
        .lookup_required(None)
        .err()
        .expect("expected MissingProfileIdNoDefault error");
    assert_eq!(err, ProfileDispatchError::MissingProfileIdNoDefault);
}
