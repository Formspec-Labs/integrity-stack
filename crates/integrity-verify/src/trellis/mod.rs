// Task 3C.1 (refactor): this crate is being split into the universal
// phase (`integrity-verify`) plus the WOS / Trellis-specific profile
// plugin (`trellis-verify-wos`). Today's `trellis-verify` still hosts
// the legacy genesis-append + export-bundle paths; the universal
// pieces (envelope shape, JCS canonical digest, bundle structural
// ordering, chain continuity, and profile-verifier handoff live in
// `integrity-verify::{cose, canonical, bundle, chain, profile,
// verify_universal}`. Subsequent tasks (3C.2 `substrate_tier`, 3C.3
// profile handoff) finish the move; the functions in this
// file marked `// NEXT TO MOVE TO integrity-verify` below are the
// migration map.
//
// NEXT TO MOVE TO integrity-verify:
// - `verify_signature` (line ~918): structural Ed25519 verification —
//   superseded by `integrity_cose::verify_ed25519_sign1`.
// - `verify_single_event` (line ~197): one-event verifier — becomes a
//   wrapper over `integrity_verify::verify_universal` with a registered
//   WOS profile.
// - The `previous_hash` / sequence continuity sub-block inside
//   `verify_event_set_with_classes` (lines ~643-687): replaceable with
//   `integrity_verify::chain::ChainContinuityCheck`.
// - `export.rs` deterministic-bundle path checks: replaceable with
//   `integrity_verify::bundle::BundleStructuralCheck`.

use std::collections::BTreeMap;

use ed25519_dalek::ed25519::signature::Verifier;

use ed25519_dalek::{Signature, VerifyingKey};

use integrity_cose::sig_structure_bytes;

use trellis_types::{
    ArtifactType, CONTENT_DOMAIN, CborHelperError, SUITE_ID_PHASE_1, domain_separated_sha256,
};

/// Re-exports the universal verifier surface so downstream callers can
/// reach `integrity-verify` without an extra direct dependency. The
/// WOS / Trellis-specific profile plugin (`trellis-verify-wos`) can
/// implement `ProfileVerifier` against this trait.
pub use crate::{
    BundleEntryView as UniversalBundleEntryView, BundleStructuralCheck as UniversalBundleCheck,
    CanonicalCheck as UniversalCanonicalCheck,
    CanonicalDigestCheck as UniversalCanonicalDigestCheck, ChainContinuityCheck,
    ChainEventView as UniversalChainEventView, CoseEnvelopeCheck, ProfileRegistry,
    ProfileVerificationResult, ProfileVerifier, UniversalFailureKind,
    VerificationReport as UniversalVerificationReport, VerifyBundleInput as UniversalVerifyInput,
    VerifyEvent as UniversalVerifyEvent, verify_universal,
};

pub(crate) mod kinds;

pub(crate) mod types;

pub(crate) mod parse;

pub(crate) mod merkle;

pub(crate) mod erasure;

pub(crate) mod certificate;

pub mod certificate_proof;

pub(crate) mod correction;

pub(crate) mod user_attestation;

pub(crate) mod interop_sidecar;

pub(crate) mod supersession;

pub(crate) mod open_clocks;

pub(crate) mod export;

pub(crate) mod util;

pub mod validator;

use crate::trellis::certificate::finalize_certificates_of_completion;
use crate::trellis::correction::finalize_correction_preservations;
use crate::trellis::erasure::finalize_erasure_evidence;
use crate::trellis::merkle::recompute_author_event_hash;
use crate::trellis::parse::{
    decode_event_details, decode_event_details_with_identity_admission, event_identity,
    parse_custody_model, parse_disclosure_profile, parse_key_registry, parse_sign1_array,
    parse_sign1_bytes,
};
use crate::trellis::user_attestation::finalize_user_content_attestations;
use crate::trellis::util::{hex_string, requires_dual_attestation};

pub use export::*;
pub use kinds::{VerificationFailureKind, VerifyErrorKind};
pub use types::*;
pub use validator::{
    DomainEvent, DomainExport, DomainFinding, RecordValidator, Severity, VerificationWithDomain,
};

const SUITE_ID_PHASE_1_I128: i128 = SUITE_ID_PHASE_1 as i128;

const ALG_EDDSA: i128 = -8;

const MERKLE_LEAF_DOMAIN: &str = "trellis-merkle-leaf-v1";

const MERKLE_INTERIOR_DOMAIN: &str = "trellis-merkle-interior-v1";

const POSTURE_DECLARATION_DOMAIN: &str = "trellis-posture-declaration-v1";

const ATTACHMENT_EXPORT_EXTENSION: &str = "trellis.export.attachments.v1";

const ATTACHMENT_EVENT_EXTENSION: &str = "trellis.evidence-attachment-binding.v1";

const ERASURE_EVIDENCE_EVENT_EXTENSION: &str = "trellis.erasure-evidence.v1";

const ERASURE_EVIDENCE_EXPORT_EXTENSION: &str = "trellis.export.erasure-evidence.v1";

/// ADR 0007 §6.7 registration — `EventPayload.extensions` slot for
/// certificate-of-completion records. Per-certificate inline shape per
/// `CertificateOfCompletionPayload` in ADR 0007 §"Wire shape".
const CERTIFICATE_EVENT_EXTENSION: &str = "trellis.certificate-of-completion.v1";

/// ADR 0007 §"Export manifest catalog" — optional manifest extension binding
/// `065-certificates-of-completion.cbor`.
const CERTIFICATE_EXPORT_EXTENSION: &str = "trellis.export.certificates-of-completion.v1";

/// ADR 0007 §9.8 / Core §9 — domain-separation tag for the SHA-256 preimage
/// covering rendered presentation-artifact bytes (PDF / HTML).
const PRESENTATION_ARTIFACT_DOMAIN: &str = "trellis-presentation-artifact-v1";

/// ADR 0010 §6.7 registration — `EventPayload.extensions` slot for
/// user-content-attestation records. Per-attestation inline shape per
/// `UserContentAttestationPayload` in Core §28 (CDDL) / ADR 0010 §"Wire shape".
const USER_CONTENT_ATTESTATION_EVENT_EXTENSION: &str = "trellis.user-content-attestation.v1";

/// ADR 0066 / Core §6.7 cross-chain supersession linkage. Event-level shape
/// is `SupersedesChainIdPayload { chain_id, checkpoint_hash }`; export-level
/// graph binding lives under [`SUPERSESSION_GRAPH_EXPORT_EXTENSION`].
const SUPERSEDES_CHAIN_ID_EVENT_EXTENSION: &str = "trellis.supersedes-chain-id.v1";

/// ADR 0066 / Core §18.3b manifest extension binding
/// `064-supersession-graph.json`.
const SUPERSESSION_GRAPH_EXPORT_EXTENSION: &str = "trellis.export.supersession-graph.v1";

/// ADR 0067 / Core §18.3c manifest extension binding `open-clocks.json`.
const OPEN_CLOCKS_EXPORT_EXTENSION: &str = "trellis.export.open-clocks.v1";

/// ADR 0010 §9.8 / Core §9 — domain-separation tag for the Ed25519 signature
/// preimage carried by `UserContentAttestationPayload.signature`. Distinct
/// from `trellis-transition-attestation-v1` so a wrongly-typed user-content
/// attestation cannot cross-validate against the operator-actor
/// posture-transition family (and vice versa). Per ADR 0010 §"Verifier
/// obligations" step 5 the inner preimage is `dCBOR([attestation_id,
/// attested_event_hash, attested_event_position, attestor,
/// identity_attestation_ref, signing_intent, attested_at])`.
const USER_CONTENT_ATTESTATION_DOMAIN: &str = "trellis-user-content-attestation-v1";

/// Phase-1 deployment-local identity-attestation event-type convention. The
/// Trellis Working Group reserves `x-trellis-test/*` (Core §6.7 + §10.6) for
/// conformance fixtures; this constant pins the literal the fixture corpus
/// mints so `is_identity_attestation_event_type` admits it. Consumer-owned
/// identity event taxonomies are admitted through the `RecordValidator` seam.
const PHASE_1_TEST_IDENTITY_EVENT_TYPE: &str = "x-trellis-test/identity-attestation/v1";

/// Operator URI scheme convention for the Phase-1 Companion §6.4 enforcement
/// of step 8 (operator-as-attestor forbidden in user-content-attestation
/// `attestor` slots). The `urn:trellis:operator:` prefix is the fixture
/// corpus's stand-in for a real operator-principal registry; deployments
/// substitute their canonical operator-URI scheme. Recognized prefixes here
/// are the conservative Phase-1 set; lint enforcement tightens before
/// deployment per ADR 0010 §"Adversary model" "operator masquerading as
/// user" mitigation.
const OPERATOR_URI_PREFIX_TRELLIS: &str = "urn:trellis:operator:";

const OPERATOR_URI_PREFIX_WOS: &str = "urn:wos:operator:";

/// Domain separation tag for transition-attestation preimages (Core §9.8).
/// Shared verbatim between §A.5 posture transitions and ADR 0005 erasure
/// evidence; Phase-1 verifier checks structural shape (`signature` is 64
/// bytes, `authority_class` is one of `prior` / `new`) — full Ed25519
/// crypto-verification of attestation signatures rides Phase-2+ when an
/// authority↔key registry binding lands. Mirrors the existing
/// posture-transition flow: presence + class-count today, crypto later.
#[allow(dead_code)]
const TRANSITION_ATTESTATION_DOMAIN: &str = "trellis-transition-attestation-v1";

/// Reserved CascadeScope identifiers from Companion Appendix A.7. Free-text
/// scope values are non-conformant per OC-141 (Companion §20.6.3 / TR-OP-106);
/// registry-extension `tstr` values that follow the Appendix A.7 convention
/// are admitted (Phase-1 reference verifier accepts any `tstr` shape; deep
/// registry-membership lint rides O-3 evolution).
#[allow(dead_code)]
const APPENDIX_A7_CASCADE_SCOPES: &[&str] = &["CS-01", "CS-02", "CS-03", "CS-04", "CS-05", "CS-06"];

/// ADR 0008 closed kind registry. New kinds land via ADR revision; this
/// constant updates in lockstep with the ADR's "Registry — Initial
/// entries" section. Order is alphabetic for grep stability; not
/// semantically ordered.
const INTEROP_SIDECAR_KIND_C2PA_MANIFEST: &str = "c2pa-manifest";

const INTEROP_SIDECAR_KIND_DID_KEY_VIEW: &str = "did-key-view";

const INTEROP_SIDECAR_KIND_SCITT_RECEIPT: &str = "scitt-receipt";

const INTEROP_SIDECAR_KIND_VC_JOSE_COSE_EVENT: &str = "vc-jose-cose-event";

/// ADR 0008 §"Export bundle layout" — sidecar files live under a single
/// `interop-sidecars/` tree at the export root. Manifest-listed paths
/// MUST start with this byte prefix (TR-CORE-167). Path is checked as
/// raw bytes; no normalization.
const INTEROP_SIDECARS_PATH_PREFIX: &str = "interop-sidecars/";

/// Wave 25: `c2pa-manifest@v1` dispatches to the digest-binding path.
/// Bumping the supported set is a wire-breaking event per ISC-06; bumps
/// land in this constant + the ADR + a new `derivation_version = 2`
/// test suite, in lockstep.
const INTEROP_SIDECAR_C2PA_MANIFEST_SUPPORTED_VERSIONS: &[u8] = &[1];

/// Wave 29: `did-key-view@v1` dispatches to the same digest-binding path.
const INTEROP_SIDECAR_DID_KEY_VIEW_SUPPORTED_VERSIONS: &[u8] = &[1];

impl std::error::Error for VerifyError {}

impl From<CborHelperError> for VerifyError {
    fn from(error: CborHelperError) -> Self {
        VerifyError::new(error.0)
    }
}

/// Verifies one COSE_Sign1 event against one Ed25519 public key.
///
/// # Errors
/// Returns an error when the signed bytes do not decode as a COSE_Sign1 item.
pub fn verify_single_event(
    public_key_bytes: [u8; 32],
    signed_event: &[u8],
) -> Result<VerificationReport, VerifyError> {
    Ok(verify_single_event_with_validator(public_key_bytes, signed_event, &())?.trellis)
}

/// Verifies one COSE_Sign1 event and runs a domain validator.
///
/// # Errors
/// Returns an error when the signed bytes do not decode as a COSE_Sign1 item.
pub fn verify_single_event_with_validator(
    public_key_bytes: [u8; 32],
    signed_event: &[u8],
    validator: &dyn RecordValidator,
) -> Result<VerificationWithDomain, VerifyError> {
    let parsed = parse_sign1_bytes(signed_event)?;
    let mut registry = BTreeMap::new();
    registry.insert(
        parsed.kid.clone(),
        SigningKeyEntry {
            public_key: public_key_bytes,
            status: 0,
            valid_from: None,
            valid_to: None,
        },
    );
    Ok(verify_event_set_with_domain(
        &[parsed],
        &registry,
        None,
        None,
        false,
        None,
        None,
        validator,
    ))
}

/// Verifies a tamper-fixture ledger plus its local key registry.
///
/// # Errors
/// Returns an error when the registry bytes cannot be decoded.
pub fn verify_tampered_ledger(
    signing_key_registry: &[u8],
    ledger: &[u8],
    initial_posture_declaration: Option<&[u8]>,
    posture_declaration: Option<&[u8]>,
) -> Result<VerificationReport, VerifyError> {
    Ok(verify_tampered_ledger_with_validator(
        signing_key_registry,
        ledger,
        initial_posture_declaration,
        posture_declaration,
        &(),
    )?
    .trellis)
}

/// Verifies a tamper-fixture ledger and runs a domain validator.
///
/// # Errors
/// Returns an error when the registry bytes cannot be decoded.
pub fn verify_tampered_ledger_with_validator(
    signing_key_registry: &[u8],
    ledger: &[u8],
    initial_posture_declaration: Option<&[u8]>,
    posture_declaration: Option<&[u8]>,
    validator: &dyn RecordValidator,
) -> Result<VerificationWithDomain, VerifyError> {
    // Surface typed structural shape failures (e.g.
    // `key_entry_attributes_shape_mismatch`, TR-CORE-048) as a
    // `VerificationReport` with the matching `tamper_kind` rather than
    // an `Err(VerifyError)` that would panic the conformance harness.
    // Untyped decode errors continue to bubble as `Err` so callers
    // distinguish "registry was structurally invalid in a known
    // tamper-detectable way" from "we could not parse the bytes at all".
    let (registry, non_signing) = match parse_key_registry(signing_key_registry) {
        Ok(maps) => maps,
        Err(error) => {
            if let Some(kind) = error.kind() {
                return Ok(VerificationWithDomain {
                    trellis: VerificationReport::fatal(
                        kind.verification_failure_kind(),
                        format!("failed to decode signing-key registry: {error}"),
                    ),
                    domain_findings: Vec::new(),
                });
            }
            return Err(error);
        }
    };
    let events = match parse_sign1_array(ledger) {
        Ok(events) => events,
        Err(error) => {
            return Ok(VerificationWithDomain {
                trellis: VerificationReport::fatal(
                    error.kind().map_or(
                        VerificationFailureKind::MalformedCose,
                        VerifyErrorKind::verification_failure_kind,
                    ),
                    error.to_string(),
                ),
                domain_findings: Vec::new(),
            });
        }
    };
    if events.is_empty() {
        return Ok(VerificationWithDomain {
            trellis: VerificationReport::fatal(
                VerificationFailureKind::MalformedCose,
                "ledger is not a non-empty dCBOR array of COSE_Sign1 events",
            ),
            domain_findings: Vec::new(),
        });
    }

    Ok(verify_event_set_with_classes(
        &events,
        &registry,
        VerifyEventSetOptions {
            non_signing_registry: Some(&non_signing),
            initial_posture_declaration,
            posture_declaration,
            classify_tamper: true,
            expected_ledger_scope: None,
            payload_blobs: None,
            record_validator: validator,
        },
    ))
}

#[allow(dead_code)]
pub(crate) fn verify_event_set(
    events: &[ParsedSign1],
    registry: &BTreeMap<Vec<u8>, SigningKeyEntry>,
    initial_posture_declaration: Option<&[u8]>,
    posture_declaration: Option<&[u8]>,
    classify_tamper: bool,
    expected_ledger_scope: Option<&[u8]>,
    payload_blobs: Option<&BTreeMap<[u8; 32], Vec<u8>>>,
) -> VerificationReport {
    verify_event_set_with_domain(
        events,
        registry,
        initial_posture_declaration,
        posture_declaration,
        classify_tamper,
        expected_ledger_scope,
        payload_blobs,
        &(),
    )
    .trellis
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_event_set_with_domain(
    events: &[ParsedSign1],
    registry: &BTreeMap<Vec<u8>, SigningKeyEntry>,
    initial_posture_declaration: Option<&[u8]>,
    posture_declaration: Option<&[u8]>,
    classify_tamper: bool,
    expected_ledger_scope: Option<&[u8]>,
    payload_blobs: Option<&BTreeMap<[u8; 32], Vec<u8>>>,
    validator: &dyn RecordValidator,
) -> VerificationWithDomain {
    verify_event_set_with_classes(
        events,
        registry,
        VerifyEventSetOptions {
            non_signing_registry: None,
            initial_posture_declaration,
            posture_declaration,
            classify_tamper,
            expected_ledger_scope,
            payload_blobs,
            record_validator: validator,
        },
    )
}

pub(crate) fn verify_event_set_with_classes(
    events: &[ParsedSign1],
    registry: &BTreeMap<Vec<u8>, SigningKeyEntry>,
    options: VerifyEventSetOptions<'_>,
) -> VerificationWithDomain {
    let VerifyEventSetOptions {
        non_signing_registry,
        initial_posture_declaration,
        posture_declaration,
        classify_tamper,
        expected_ledger_scope,
        payload_blobs,
        record_validator,
    } = options;
    let mut event_failures = Vec::new();
    let mut domain_events = Vec::new();
    let mut posture_transitions = Vec::new();
    let mut previous_hash: Option<[u8; 32]> = None;
    let mut previous_authored_at: Option<TrellisTimestamp> = None;
    let skip_prev_hash_check = initial_posture_declaration.is_some() && events.len() == 1;

    // Core §17.3 — Track every `(ledger_scope, idempotency_key)` identity
    // seen so far in this event set, mapped to the first canonical event's
    // `canonical_event_hash`. A second event sharing the identity but with
    // a divergent `canonical_event_hash` is a §17.3 clause-3 violation
    // surfaced as `idempotency_key_payload_mismatch` (§17.5 + TR-CORE-160).
    // The check is offline (Core §16) and operates purely on the canonical
    // events; no Canonical Append Service state is required.
    let mut idempotency_index: BTreeMap<(Vec<u8>, Vec<u8>), [u8; 32]> = BTreeMap::new();
    let mut shadow_custody_model =
        initial_posture_declaration.and_then(|bytes| parse_custody_model(bytes).ok());
    let mut shadow_disclosure_profile =
        initial_posture_declaration.and_then(|bytes| parse_disclosure_profile(bytes).ok());

    // ADR 0005 cross-event finalization inputs.
    // - `erasure_payloads` collects every decoded erasure-evidence event for
    //   the post-loop finalize pass (steps 2 / 5 / 7 / 8 / 10).
    // - `chain_summaries` carries every event's (authored_at, signing kid,
    //   wrap recipients, canonical_event_hash) tuple so step 8 (chain
    //   consistency for the destroyed kid) can flag post_erasure_use /
    //   post_erasure_wrap.
    let mut erasure_payloads: Vec<(usize, ErasureEvidenceDetails, [u8; 32])> = Vec::new();
    let mut chain_summaries: Vec<ChainEventSummary> = Vec::with_capacity(events.len());

    // ADR 0007 certificate-of-completion finalization input. `(event_index,
    // CertificateDetails, canonical_event_hash)` tuples — same shape as
    // `erasure_payloads`. The post-loop pass cross-references against the
    // chain to run steps 2 (id collision), 5 (signing-event resolution),
    // 6 (timestamp equivalence), and 7 (response_ref equivalence). Step 4
    // (attachment lineage + content recompute) requires payload-blob access
    // and runs in the export-bundle path only; the genesis-append path
    // marks `attachment_resolved = true` and `failures = []` per ADR 0007
    // §"Verifier obligations" Phase-1 minimal-genesis posture.
    let mut certificate_payloads: Vec<(usize, CertificateDetails, [u8; 32])> = Vec::new();

    // ADR 0010 user-content-attestation finalization input. `(event_index,
    // UserContentAttestationDetails, canonical_event_hash)` tuples —
    // same shape as `erasure_payloads` / `certificate_payloads`. Per-event
    // CDDL decode + signing_intent URI well-formedness + attested_at-equals-
    // authored_at run inline at decode time; the post-loop pass cross-
    // references against the chain to run steps 3 (chain-position resolution),
    // 4 (identity resolution), 5 (signature verification), 6 (key-state
    // check), 7 (collision detection), 8 (operator-in-user-slot enforcement),
    // and 9 (outcome accumulation).
    let mut user_content_attestation_payloads: Vec<(
        usize,
        UserContentAttestationDetails,
        [u8; 32],
    )> = Vec::new();

    // Decoded event payloads indexed by chain position. Finalize passes reuse
    // these instead of re-decoding every `ParsedSign1`; indices the main loop
    // skipped still decode here so digest-resolution matches the legacy path
    // for events that failed signature verification but remain structurally
    // parseable.
    let mut decoded_per_index: Vec<Option<EventDetails>> = vec![None; events.len()];

    for (index, event) in events.iter().enumerate() {
        let key_entry = match registry.get(&event.kid) {
            Some(entry) => entry,
            None => {
                // Core §8.7.3 step 4: if the kid resolves to a reserved
                // non-signing class, this is `key_class_mismatch` rather
                // than `unresolvable_manifest_kid`. Recovery-only keys are
                // the canonical class-confusion attack surface; tenant-root
                // / scope / subject kids signing ordinary events are also
                // class violations under the unified taxonomy.
                if let Some(non_signing) = non_signing_registry.and_then(|map| map.get(&event.kid))
                {
                    return VerificationWithDomain {
                        trellis: VerificationReport::fatal(
                            VerificationFailureKind::KeyClassMismatch,
                            format!(
                                "event signed under a `{}`-class kid; only `signing` keys may sign canonical events (Core §8.7.3 step 4)",
                                non_signing.class
                            ),
                        ),
                        domain_findings: Vec::new(),
                    };
                }
                return VerificationWithDomain {
                    trellis: VerificationReport::fatal(
                        VerificationFailureKind::UnresolvableManifestKid,
                        "event kid is not resolvable via the provided signing-key registry",
                    ),
                    domain_findings: Vec::new(),
                };
            }
        };
        if event.alg != ALG_EDDSA
            || event.suite_id != SUITE_ID_PHASE_1_I128
            || event.artifact_type != ArtifactType::Event
        {
            return VerificationWithDomain {
                trellis: VerificationReport::fatal(
                    VerificationFailureKind::UnsupportedSuite,
                    format!(
                        "event protected header does not match the Trellis Phase-1 event suite; artifact_type={}",
                        event.artifact_type
                    ),
                ),
                domain_findings: Vec::new(),
            };
        }
        if !verify_signature(event, key_entry.public_key) {
            let location = event_identity(event)
                .map(|(_, hash)| hex_string(&hash))
                .unwrap_or_else(|_| format!("event[{index}]"));
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::SignatureInvalid,
                location,
            ));
            continue;
        }

        let identity_event_type_admitted =
            |event_type: &str| record_validator.admits_identity_attestation_event_type(event_type);
        let decoded = match decode_event_details_with_identity_admission(
            event,
            &identity_event_type_admitted,
        ) {
            Ok(details) => details,
            Err(error) => {
                // Surface typed structural-failure kinds (e.g.
                // `erasure_destroyed_at_after_host` from ADR 0005 step 4)
                // as the report's `tamper_kind`. Untyped decode errors
                // continue to land as the generic `malformed_cose` for
                // back-compat with existing fixtures.
                let failure_kind = error
                    .kind()
                    .map(VerifyErrorKind::verification_failure_kind)
                    .unwrap_or(VerificationFailureKind::MalformedCose);
                let warning = if error.kind().is_some() {
                    error.to_string()
                } else {
                    "event payload does not decode as a canonical Trellis event".to_string()
                };
                return VerificationWithDomain {
                    trellis: VerificationReport::fatal(failure_kind, warning),
                    domain_findings: Vec::new(),
                };
            }
        };
        decoded_per_index[index] = Some(decoded);
        let Some(details) = decoded_per_index
            .get_mut(index)
            .and_then(|slot| slot.as_mut())
        else {
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::MalformedCose,
                format!("event[{index}]"),
            ));
            continue;
        };

        if key_entry.status == 3 {
            match key_entry.valid_to {
                Some(valid_to) if details.authored_at > valid_to => {
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::RevokedAuthority,
                        hex_string(&details.canonical_event_hash),
                    ));
                }
                None => {
                    return VerificationWithDomain {
                        trellis: VerificationReport::fatal(
                            VerificationFailureKind::SigningKeyRegistryInvalid,
                            "revoked signing-key registry entry is missing valid_to",
                        ),
                        domain_findings: Vec::new(),
                    };
                }
                // Key is revoked, but this event was authored on or before
                // `valid_to` — accepted per Core §19 (historical signatures).
                _ => {}
            }
        }

        if let Some(expected) = expected_ledger_scope
            && details.scope.as_slice() != expected
        {
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ScopeMismatch,
                hex_string(&details.canonical_event_hash),
            ));
        }

        // Core §17.3 clause 3 + §17.5 — duplicate `(scope, idempotency_key)`
        // identity with divergent canonical material is `idempotency_key_payload_mismatch`.
        // The first occurrence is admitted as the canonical reference; the
        // second occurrence is the failing event. Identity is determined by
        // (scope, idempotency_key); divergence is by canonical_event_hash
        // (which transitively binds content_hash + author_event_hash via
        // §9.2 / §9.5 preimages). TR-CORE-160 + TR-CORE-162.
        let identity_key = (details.scope.clone(), details.idempotency_key.clone());
        match idempotency_index.get(&identity_key) {
            Some(prior_hash) if *prior_hash != details.canonical_event_hash => {
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::IdempotencyKeyPayloadMismatch,
                    hex_string(&details.canonical_event_hash),
                ));
            }
            Some(_) => {
                // Same identity, byte-equal canonical hash — §17.3 clause 1
                // (same canonical reference) / clause 2 (declared no-op).
                // Phase 1 ledgers SHOULD NOT carry duplicate entries, but a
                // byte-equal duplicate is a no-op rather than a tamper.
            }
            None => {
                idempotency_index.insert(identity_key, details.canonical_event_hash);
            }
        }

        match &details.payload_ref {
            PayloadRef::Inline(ciphertext) => {
                let expected_content_hash = domain_separated_sha256(CONTENT_DOMAIN, ciphertext);
                if expected_content_hash != details.content_hash {
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ContentHashMismatch,
                        hex_string(&details.canonical_event_hash),
                    ));
                }
            }
            PayloadRef::External => {
                if let Some(blobs) = payload_blobs
                    && let Some(payload_bytes) = blobs.get(&details.content_hash)
                {
                    let expected_content_hash =
                        domain_separated_sha256(CONTENT_DOMAIN, payload_bytes);
                    if expected_content_hash != details.content_hash {
                        event_failures.push(VerificationFailure::new(
                            VerificationFailureKind::ContentHashMismatch,
                            hex_string(&details.canonical_event_hash),
                        ));
                    }
                }
            }
        }

        let payload_bytes = match event.payload.as_ref() {
            Some(bytes) => bytes.as_slice(),
            None => {
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::MalformedCose,
                    format!("event[{index}]"),
                ));
                continue;
            }
        };
        match recompute_author_event_hash(payload_bytes) {
            Some(expected_author_hash) if expected_author_hash == details.author_event_hash => {}
            Some(_) => {
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::HashMismatch,
                    hex_string(&details.canonical_event_hash),
                ));
            }
            None => {
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::AuthorPreimageInvalid,
                    hex_string(&details.canonical_event_hash),
                ));
            }
        }

        if skip_prev_hash_check {
        } else if details.sequence == 0 {
            if details.prev_hash.is_some() {
                let kind = if classify_tamper {
                    VerificationFailureKind::EventReorder
                } else {
                    VerificationFailureKind::PrevHashMismatch
                };
                event_failures.push(VerificationFailure::new(
                    kind,
                    hex_string(&details.canonical_event_hash),
                ));
            }
        } else if previous_hash != details.prev_hash {
            let kind = if classify_tamper {
                if previous_hash.is_none() && events.len() == 1 {
                    VerificationFailureKind::EventTruncation
                } else if previous_hash.is_none() {
                    VerificationFailureKind::EventReorder
                } else {
                    VerificationFailureKind::PrevHashBreak
                }
            } else {
                VerificationFailureKind::PrevHashMismatch
            };
            event_failures.push(VerificationFailure::new(
                kind,
                hex_string(&details.canonical_event_hash),
            ));
        }
        previous_hash = Some(details.canonical_event_hash);

        // ADR 0069 D-3 — timestamps must be non-decreasing along chain
        // order. Equal timestamps are permitted; chain position
        // disambiguates. A backwards timestamp is an integrity failure
        // distinct from hash/signature tamper (Core §19 step 4.h-temporal).
        if let Some(prev_at) = previous_authored_at
            && details.authored_at < prev_at
        {
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::TimestampOrderViolation,
                hex_string(&details.canonical_event_hash),
            ));
        }
        previous_authored_at = Some(details.authored_at);

        // ADR 0005 step 8 input collection — every event contributes a
        // chain summary so the post-loop pass can flag `authored_at >
        // destroyed_at` events that sign under (post_erasure_use) or wrap
        // for (post_erasure_wrap) a destroyed kid.
        chain_summaries.push(ChainEventSummary {
            event_index: index as u64,
            authored_at: details.authored_at,
            signing_kid: event.kid.clone(),
            wrap_recipients: details.wrap_recipients.clone(),
            canonical_event_hash: details.canonical_event_hash,
        });
        if let Some(erasure) = details.take_erasure() {
            erasure_payloads.push((index, erasure, details.canonical_event_hash));
        }
        if let Some(certificate) = details.take_certificate() {
            certificate_payloads.push((index, certificate, details.canonical_event_hash));
        }
        if let Some(uca) = details.take_user_content_attestation() {
            user_content_attestation_payloads.push((index, uca, details.canonical_event_hash));
        }

        domain_events.push(DomainEvent {
            event_type: details.event_type.clone(),
            payload: readable_payload_for_domain(details, payload_blobs),
            canonical_event_hash: details.canonical_event_hash,
            authored_at: details.authored_at,
        });

        if let Some(transition) = details.take_transition() {
            let mut outcome = PostureTransitionOutcome {
                transition_id: transition.transition_id.clone(),
                kind: transition.kind.as_report_str().to_string(),
                event_index: index as u64,
                from_state: transition.from_state.clone(),
                to_state: transition.to_state.clone(),
                continuity_verified: true,
                declaration_resolved: true,
                attestations_verified: true,
                failures: Vec::new(),
            };

            let shadow_state = match transition.kind {
                TransitionKind::CustodyModel => shadow_custody_model.clone(),
                TransitionKind::DisclosureProfile => shadow_disclosure_profile.clone(),
            };
            if let Some(initial_state) = shadow_state
                && transition.from_state != initial_state
            {
                outcome.continuity_verified = false;
                outcome.failures.push("state_continuity_mismatch".into());
            }

            if let Some(declaration_bytes) = posture_declaration {
                let expected_declaration_digest =
                    domain_separated_sha256(POSTURE_DECLARATION_DOMAIN, declaration_bytes);
                if expected_declaration_digest != transition.declaration_digest {
                    outcome.continuity_verified = false;
                    outcome.declaration_resolved = false;
                    outcome
                        .failures
                        .push("posture_declaration_digest_mismatch".into());
                }
            }

            let dual_required = match transition.kind {
                TransitionKind::CustodyModel => {
                    requires_dual_attestation(&transition.from_state, &transition.to_state)
                }
                TransitionKind::DisclosureProfile => {
                    // Appendix A.5.3 step 4: Narrowing MAY be attested by the
                    // new authority alone; Widening and Orthogonal MUST be
                    // dually attested. Unknown values fall through to dual
                    // as the conservative default.
                    match transition.scope_change.as_deref() {
                        Some("Narrowing") => false,
                        Some("Widening") | Some("Orthogonal") => true,
                        _ => true,
                    }
                }
            };
            if dual_required
                && !(transition
                    .attestation_classes
                    .iter()
                    .any(|value| value == "prior")
                    && transition
                        .attestation_classes
                        .iter()
                        .any(|value| value == "new"))
            {
                outcome.attestations_verified = false;
                outcome.failures.push("attestation_insufficient".into());
            }

            if let Some(first_failure) = outcome.failures.first() {
                let failure_kind = match first_failure.as_str() {
                    "state_continuity_mismatch" => VerificationFailureKind::StateContinuityMismatch,
                    "posture_declaration_digest_mismatch" => {
                        VerificationFailureKind::PostureDeclarationDigestMismatch
                    }
                    "attestation_insufficient" => VerificationFailureKind::AttestationInsufficient,
                    _ => VerificationFailureKind::MalformedCose,
                };
                event_failures.push(VerificationFailure::new(
                    failure_kind,
                    hex_string(&details.canonical_event_hash),
                ));
            }
            match transition.kind {
                TransitionKind::CustodyModel => {
                    shadow_custody_model = Some(transition.to_state.clone());
                }
                TransitionKind::DisclosureProfile => {
                    shadow_disclosure_profile = Some(transition.to_state.clone());
                }
            }
            posture_transitions.push(outcome);
        }
    }

    let erasure_evidence = finalize_erasure_evidence(
        &erasure_payloads,
        &chain_summaries,
        registry,
        non_signing_registry,
        &mut event_failures,
    );

    let correction_preservations = finalize_correction_preservations(events, payload_blobs);
    let (event_lookup_pool, event_by_hash_idx, event_by_position_idx) =
        build_event_details_lookup(events, decoded_per_index);

    // ADR 0007 certificate-of-completion finalization (steps 2 / 5 / 6 / 7 /
    // 8 cross-event reasoning). Step 4 (attachment lineage + content
    // recompute) defers to the export-bundle path; the genesis-append path
    // accumulates outcomes with `attachment_resolved = true` so the §19
    // step-9 fold doesn't false-positive on minimal-genesis fixtures.
    let certificates_of_completion = finalize_certificates_of_completion(
        &certificate_payloads,
        &event_lookup_pool,
        &event_by_hash_idx,
        payload_blobs,
        record_validator.response_proof_resolver(),
        &mut event_failures,
    );

    // ADR 0010 user-content-attestation finalization (Core §19 step 6d
    // steps 3 / 4 / 5 / 6 / 7 / 8 / 9 cross-event reasoning).
    let user_content_attestations = finalize_user_content_attestations(
        &user_content_attestation_payloads,
        &event_lookup_pool,
        &event_by_hash_idx,
        &event_by_position_idx,
        registry,
        posture_declaration,
        record_validator,
        &mut event_failures,
    );

    let trellis = VerificationReport::from_integrity_state(
        event_failures,
        Vec::new(),
        Vec::new(),
        posture_transitions,
        erasure_evidence,
        certificates_of_completion,
        user_content_attestations,
        correction_preservations,
        Vec::new(),
    );
    let domain_findings = record_validator.validate_events(&domain_events);
    VerificationWithDomain {
        trellis,
        domain_findings,
    }
}

fn readable_payload_for_domain(
    details: &EventDetails,
    payload_blobs: Option<&BTreeMap<[u8; 32], Vec<u8>>>,
) -> Option<Vec<u8>> {
    match &details.payload_ref {
        PayloadRef::Inline(bytes) => Some(bytes.clone()),
        PayloadRef::External => {
            payload_blobs.and_then(|blobs| blobs.get(&details.content_hash).cloned())
        }
    }
}

pub(crate) type EventDetailsLookupPools = (
    Vec<EventDetails>,
    BTreeMap<[u8; 32], usize>,
    BTreeMap<(Vec<u8>, u64), usize>,
);

/// Indexes decoded [`EventDetails`] for certificate / user-content-attestation
/// finalize passes. Prefers per-event decodes from [`verify_event_set_with_classes`];
/// fills gaps by decoding wire events so behavior matches the legacy
/// finalize-only path for chain indices the main loop never decoded.
pub(crate) fn build_event_details_lookup(
    events: &[ParsedSign1],
    mut decoded_per_index: Vec<Option<EventDetails>>,
) -> EventDetailsLookupPools {
    let mut pool: Vec<EventDetails> = Vec::with_capacity(events.len());
    let mut by_hash: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut by_position: BTreeMap<(Vec<u8>, u64), usize> = BTreeMap::new();

    for (idx, event) in events.iter().enumerate() {
        let decoded = match decoded_per_index.get_mut(idx).and_then(|slot| slot.take()) {
            Some(details) => details,
            None => match decode_event_details(event) {
                Ok(details) => details,
                Err(_) => continue,
            },
        };
        let canon = decoded.canonical_event_hash;
        if by_hash.contains_key(&canon) {
            continue;
        }
        let pos_key = (decoded.scope.clone(), decoded.sequence);
        let entry_idx = pool.len();
        pool.push(decoded);
        by_hash.insert(canon, entry_idx);
        by_position.entry(pos_key).or_insert(entry_idx);
    }

    (pool, by_hash, by_position)
}

pub(crate) fn verify_signature(item: &ParsedSign1, public_key_bytes: [u8; 32]) -> bool {
    let Some(payload) = &item.payload else {
        return false;
    };
    let signature = Signature::from_bytes(&item.signature);
    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let sig_structure = sig_structure_bytes(&item.protected_bytes, payload);
    verifying_key.verify(&sig_structure, &signature).is_ok()
}

pub(crate) fn attachment_entry_matches_binding(
    entry: &AttachmentManifestEntry,
    binding: &AttachmentBindingDetails,
) -> bool {
    entry.attachment_id == binding.attachment_id
        && entry.slot_path == binding.slot_path
        && entry.media_type == binding.media_type
        && entry.byte_length == binding.byte_length
        && entry.attachment_sha256 == binding.attachment_sha256
        && entry.payload_content_hash == binding.payload_content_hash
        && entry.filename == binding.filename
        && entry.prior_binding_hash == binding.prior_binding_hash
}

/// Reserved non-signing class literals from Core §8.7 (ADR 0006).
const RESERVED_NON_SIGNING_KIND: &[&str] = &["tenant-root", "scope", "subject", "recovery"];
