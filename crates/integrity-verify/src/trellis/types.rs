use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use crate::trellis::kinds::{VerificationFailureKind, VerifyErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrellisTimestamp {
    pub seconds: u64,
    pub nanos: u32,
}

impl PartialOrd for TrellisTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TrellisTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seconds
            .cmp(&other.seconds)
            .then_with(|| self.nanos.cmp(&other.nanos))
    }
}

impl Display for TrellisTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.seconds, self.nanos)
    }
}

/// Verification failure localized to one artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationFailure {
    pub kind: VerificationFailureKind,
    pub location: String,
}

impl VerificationFailure {
    pub(crate) fn new(kind: VerificationFailureKind, location: impl Into<String>) -> Self {
        Self {
            kind,
            location: location.into(),
        }
    }
}

/// Outcome for one posture-transition verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureTransitionOutcome {
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

/// Outcome for one cryptographic-erasure-evidence verification (ADR 0005
/// step 10 / Core §19 step 6b). One entry per `trellis.erasure-evidence.v1`
/// payload in the chain, in chain order. `post_erasure_uses` and
/// `post_erasure_wraps` count cross-event violations attributable to this
/// evidence's `kid_destroyed`; `cascade_violations` is reserved for the
/// Phase-2 deep-cascade lint (Phase-1 leaves it empty).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureEvidenceOutcome {
    pub evidence_id: String,
    pub kid_destroyed: Vec<u8>,
    pub destroyed_at: TrellisTimestamp,
    pub cascade_scopes: Vec<String>,
    pub completion_mode: String,
    pub event_index: u64,
    /// Phase-1 contract: `true` iff every attestation row carries the
    /// structural shape (64-byte `signature`, valid `authority_class`).
    /// Crypto-verification rides Phase-2+ — see Phase-1 limit comment on
    /// `TRANSITION_ATTESTATION_DOMAIN`. Parallel to the existing
    /// posture-transition flow (`PostureTransitionOutcome.attestations_verified`).
    pub signature_verified: bool,
    pub post_erasure_uses: u64,
    pub post_erasure_wraps: u64,
    pub cascade_violations: Vec<String>,
    pub failures: Vec<String>,
}

/// Outcome for one ADR 0007 certificate-of-completion verification (Core
/// §19 step 6c). One entry per `trellis.certificate-of-completion.v1`
/// payload in scope, in chain order. `attachment_resolved` /
/// `all_signing_events_resolved` / `chain_summary_consistent` are the three
/// booleans that participate in the §19 step-9 integrity fold; `failures`
/// localizes the concrete tamper kinds (e.g.
/// `signing_event_unresolved`, `presentation_artifact_content_mismatch`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateOfCompletionOutcome {
    pub certificate_id: String,
    pub event_index: u64,
    pub completed_at: TrellisTimestamp,
    pub signer_count: u64,
    pub attachment_resolved: bool,
    pub all_signing_events_resolved: bool,
    pub chain_summary_consistent: bool,
    pub failures: Vec<String>,
}

/// Outcome for one ADR 0010 user-content-attestation verification (Core
/// §19 step 6d). One entry per `trellis.user-content-attestation.v1`
/// payload in scope, in chain order. `chain_position_resolved` /
/// `identity_resolved` / `signature_verified` / `key_active` are the four
/// booleans that participate in the §19 step-9 integrity fold per ADR
/// 0010 §"Verifier obligations" step 9; `failures` localizes the concrete
/// tamper kinds (`user_content_attestation_*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserContentAttestationOutcome {
    pub attestation_id: String,
    pub attested_event_hash: [u8; 32],
    pub attestor: String,
    pub signing_intent: String,
    pub event_index: u64,
    pub chain_position_resolved: bool,
    pub identity_resolved: bool,
    pub signature_verified: bool,
    pub key_active: bool,
    pub failures: Vec<String>,
}

/// ADR 0066 correction-preservation report entry.
///
/// One entry per correction record whose readable payload is available.
/// `field_values` carries original and corrected values as canonical CBOR
/// bytes when the producer includes them; current WOS `correctionAuthorized`
/// records may carry only `target_event_hash` and `corrected_field_set` until
/// the Formspec `ResponseCorrection` producer shape lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectionPreservationOutcome {
    pub event_index: u64,
    pub correction_event_hash: [u8; 32],
    pub target_event_hash: Option<String>,
    pub corrected_field_set: Vec<String>,
    pub field_values: Vec<CorrectionFieldValue>,
}

/// One corrected field value pair in an ADR 0066 correction report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectionFieldValue {
    pub field_path: String,
    pub original_value_cbor: Vec<u8>,
    pub corrected_value_cbor: Vec<u8>,
}

/// ADR 0008 §"Phase-1 verifier obligation" per-entry interop-sidecar
/// outcome. One entry per `manifest.interop_sidecars[i]` walked under
/// Wave 25 dispatch (today: `c2pa-manifest@v1`). The struct mirrors
/// Core §28 `InteropSidecarVerificationEntry` byte-for-byte.
///
/// Path-(b) discipline (Core §18.3a / ADR 0008 §"Phase-1 verifier
/// obligation" step 3): digest-binds only — the verifier does NOT
/// resolve `source_ref` to the canonical event, decode the C2PA
/// manifest bytes, or import `c2pa-rs` (ISC-05). The C2PA-tooling-path
/// consumer is documented in `trellis-interop-c2pa/README.md` as an
/// additive verification path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InteropSidecarVerificationEntry {
    pub kind: String,
    pub path: String,
    pub derivation_version: u8,
    pub content_digest_ok: bool,
    pub kind_registered: bool,
    pub phase_1_locked: bool,
    pub failures: Vec<String>,
}

/// Verification report for the current Phase-1 runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerificationReport {
    pub structure_verified: bool,
    pub integrity_verified: bool,
    pub readability_verified: bool,
    pub event_failures: Vec<VerificationFailure>,
    pub checkpoint_failures: Vec<VerificationFailure>,
    pub proof_failures: Vec<VerificationFailure>,
    pub posture_transitions: Vec<PostureTransitionOutcome>,
    pub erasure_evidence: Vec<ErasureEvidenceOutcome>,
    pub certificates_of_completion: Vec<CertificateOfCompletionOutcome>,
    /// ADR 0010 user-content-attestation outcomes (Core §19 step 6d
    /// step 9). One entry per `trellis.user-content-attestation.v1`
    /// payload in scope, in chain order.
    pub user_content_attestations: Vec<UserContentAttestationOutcome>,
    /// ADR 0066 correction-preservation outcomes. These entries are report
    /// evidence, not integrity predicates; missing upstream value pairs remain
    /// visible as empty `field_values` rather than verifier failures.
    pub correction_preservations: Vec<CorrectionPreservationOutcome>,
    /// ADR 0008 / Core §18.3a interop-sidecar outcomes. Filled only
    /// when `interop_sidecar::verify_interop_sidecars` returns `Ok`: one
    /// entry per manifest `interop_sidecars[]` row that passes dispatch
    /// (today: successful `c2pa-manifest@v1` and `did-key-view@v1`
    /// rows). When that helper returns
    /// `Err(VerificationReport::fatal(..))`—path invalid, digest
    /// mismatch, Phase-1 lock-off, unlisted file, etc.—the export
    /// verifier returns that report immediately and this vector stays
    /// empty; see `event_failures` on that returned report. Absent or
    /// null `interop_sidecars` in the manifest yields `Ok` with an empty
    /// vector.
    pub interop_sidecars: Vec<InteropSidecarVerificationEntry>,
    pub warnings: Vec<String>,
}

impl VerificationReport {
    pub(crate) fn fatal(kind: VerificationFailureKind, warning: impl Into<String>) -> Self {
        let warning = warning.into();
        Self {
            structure_verified: false,
            integrity_verified: false,
            readability_verified: false,
            event_failures: vec![VerificationFailure::new(kind, "structure")],
            checkpoint_failures: Vec::new(),
            proof_failures: Vec::new(),
            posture_transitions: Vec::new(),
            erasure_evidence: Vec::new(),
            certificates_of_completion: Vec::new(),
            user_content_attestations: Vec::new(),
            correction_preservations: Vec::new(),
            interop_sidecars: Vec::new(),
            warnings: vec![warning],
        }
    }

    /// Single Core §19 step-9 integrity fold shared by genesis-append and
    /// export-bundle paths so posture / erasure / certificate / UCA /
    /// interop predicates cannot drift across call sites.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn integrity_verified_from_parts(
        event_failures: &[VerificationFailure],
        checkpoint_failures: &[VerificationFailure],
        proof_failures: &[VerificationFailure],
        posture_transitions: &[PostureTransitionOutcome],
        erasure_evidence: &[ErasureEvidenceOutcome],
        certificates_of_completion: &[CertificateOfCompletionOutcome],
        user_content_attestations: &[UserContentAttestationOutcome],
        interop_sidecars: &[InteropSidecarVerificationEntry],
    ) -> bool {
        let posture_ok = posture_transitions.iter().all(|outcome| {
            outcome.continuity_verified
                && outcome.declaration_resolved
                && outcome.attestations_verified
        });
        let erasure_ok = erasure_evidence.iter().all(|outcome| {
            outcome.signature_verified
                && outcome.post_erasure_uses == 0
                && outcome.post_erasure_wraps == 0
        });
        let certificate_ok = certificates_of_completion.iter().all(|outcome| {
            outcome.chain_summary_consistent
                && outcome.attachment_resolved
                && outcome.all_signing_events_resolved
        });
        let user_content_attestation_ok = user_content_attestations.iter().all(|outcome| {
            outcome.chain_position_resolved
                && outcome.identity_resolved
                && outcome.signature_verified
                && outcome.key_active
        });
        let interop_ok = interop_sidecars.iter().all(|outcome| {
            outcome.content_digest_ok
                && outcome.kind_registered
                && !outcome.phase_1_locked
                && outcome.failures.is_empty()
        });

        event_failures.is_empty()
            && checkpoint_failures.is_empty()
            && proof_failures.is_empty()
            && posture_ok
            && erasure_ok
            && certificate_ok
            && user_content_attestation_ok
            && interop_ok
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_integrity_state(
        event_failures: Vec<VerificationFailure>,
        checkpoint_failures: Vec<VerificationFailure>,
        proof_failures: Vec<VerificationFailure>,
        posture_transitions: Vec<PostureTransitionOutcome>,
        erasure_evidence: Vec<ErasureEvidenceOutcome>,
        certificates_of_completion: Vec<CertificateOfCompletionOutcome>,
        user_content_attestations: Vec<UserContentAttestationOutcome>,
        correction_preservations: Vec<CorrectionPreservationOutcome>,
        warnings: Vec<String>,
    ) -> Self {
        let integrity_verified = Self::integrity_verified_from_parts(
            &event_failures,
            &checkpoint_failures,
            &proof_failures,
            &posture_transitions,
            &erasure_evidence,
            &certificates_of_completion,
            &user_content_attestations,
            &[],
        );

        Self {
            structure_verified: true,
            integrity_verified,
            readability_verified: true,
            event_failures,
            checkpoint_failures,
            proof_failures,
            posture_transitions,
            erasure_evidence,
            certificates_of_completion,
            user_content_attestations,
            correction_preservations,
            // Genesis-append path produces no interop sidecar outcomes;
            // the export-archive path populates this slice via
            // `verify_interop_sidecars` (ADR 0008 §"Phase-1 verifier
            // obligation" — Wave 25).
            interop_sidecars: Vec::new(),
            warnings,
        }
    }
}

/// Error returned when verifier inputs cannot be decoded at all.
#[derive(Debug)]
pub struct VerifyError {
    pub(crate) message: String,
    /// Optional structural-failure discriminant for registry / decode paths.
    pub(crate) kind: Option<VerifyErrorKind>,
    pub(crate) backtrace: Backtrace,
}

impl VerifyError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: None,
            backtrace: Backtrace::capture(),
        }
    }

    pub(crate) fn with_kind(message: impl Into<String>, kind: VerifyErrorKind) -> Self {
        Self {
            message: message.into(),
            kind: Some(kind),
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns the structural-failure discriminant, if one was set.
    pub fn kind(&self) -> Option<VerifyErrorKind> {
        self.kind
    }

    /// Returns the captured backtrace for this verify failure.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedSign1 {
    pub(crate) protected_bytes: Vec<u8>,
    pub(crate) kid: Vec<u8>,
    pub(crate) alg: i128,
    pub(crate) suite_id: i128,
    pub(crate) artifact_type: trellis_types::ArtifactType,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProfileExtensionKind {
    Transition,
    AttachmentBinding,
    ErasureEvidence,
    CertificateOfCompletion,
    UserContentAttestation,
    SupersedesChainId,
    IdentityAttestationSubject,
}

#[derive(Clone, Debug)]
pub(crate) enum ProfileExtensionDetails {
    Transition(TransitionDetails),
    AttachmentBinding(AttachmentBindingDetails),
    ErasureEvidence(ErasureEvidenceDetails),
    CertificateOfCompletion(CertificateDetails),
    UserContentAttestation(UserContentAttestationDetails),
    SupersedesChainId(SupersedesChainIdDetails),
    IdentityAttestationSubject(String),
}

pub(crate) type ProfileExtensionMap = BTreeMap<ProfileExtensionKind, ProfileExtensionDetails>;

#[derive(Clone, Debug)]
pub(crate) struct EventDetails {
    pub(crate) scope: Vec<u8>,
    pub(crate) sequence: u64,
    pub(crate) authored_at: TrellisTimestamp,
    pub(crate) event_type: String,
    pub(crate) classification: String,
    pub(crate) prev_hash: Option<[u8; 32]>,
    pub(crate) author_event_hash: [u8; 32],
    pub(crate) content_hash: [u8; 32],
    pub(crate) canonical_event_hash: [u8; 32],
    /// Core §6.1 / §17.2 wire-contract identity. Length is validated against
    /// `bstr .size (1..64)` at parse time; out-of-bound length surfaces as a
    /// typed `VerifyError` with kind `idempotency_key_length_invalid`.
    /// Used by the per-event-set loop to detect §17.3 duplicate `(scope, key)`
    /// identity with divergent canonical material.
    pub(crate) idempotency_key: Vec<u8>,
    pub(crate) payload_ref: PayloadRef,
    /// Bounded decoded profile-extension payloads.
    ///
    /// The wire `EventPayload.extensions` map remains open, but the core
    /// verifier only materializes extension families it owns or dispatches.
    /// Unknown consumer profile extensions stay behind the `RecordValidator`
    /// seam instead of becoming fixed fields on this internal event summary.
    pub(crate) profile_extensions: ProfileExtensionMap,
    /// Wrap recipients from `key_bag.entries[*].recipient`. Bytes copied
    /// verbatim from the wire so step 8 can compare against `kid_destroyed`
    /// (a `bstr .size 16`) for `post_erasure_wrap` detection. Empty when
    /// the event has no key_bag entries (Phase-1 plaintext path).
    pub(crate) wrap_recipients: Vec<Vec<u8>>,
}

impl EventDetails {
    pub(crate) fn take_transition(&mut self) -> Option<TransitionDetails> {
        match self
            .profile_extensions
            .remove(&ProfileExtensionKind::Transition)
        {
            Some(ProfileExtensionDetails::Transition(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn attachment_binding(&self) -> Option<&AttachmentBindingDetails> {
        match self
            .profile_extensions
            .get(&ProfileExtensionKind::AttachmentBinding)
        {
            Some(ProfileExtensionDetails::AttachmentBinding(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn erasure(&self) -> Option<&ErasureEvidenceDetails> {
        match self
            .profile_extensions
            .get(&ProfileExtensionKind::ErasureEvidence)
        {
            Some(ProfileExtensionDetails::ErasureEvidence(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn take_erasure(&mut self) -> Option<ErasureEvidenceDetails> {
        match self
            .profile_extensions
            .remove(&ProfileExtensionKind::ErasureEvidence)
        {
            Some(ProfileExtensionDetails::ErasureEvidence(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn certificate(&self) -> Option<&CertificateDetails> {
        match self
            .profile_extensions
            .get(&ProfileExtensionKind::CertificateOfCompletion)
        {
            Some(ProfileExtensionDetails::CertificateOfCompletion(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn take_certificate(&mut self) -> Option<CertificateDetails> {
        match self
            .profile_extensions
            .remove(&ProfileExtensionKind::CertificateOfCompletion)
        {
            Some(ProfileExtensionDetails::CertificateOfCompletion(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn take_user_content_attestation(
        &mut self,
    ) -> Option<UserContentAttestationDetails> {
        match self
            .profile_extensions
            .remove(&ProfileExtensionKind::UserContentAttestation)
        {
            Some(ProfileExtensionDetails::UserContentAttestation(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn supersedes_chain(&self) -> Option<&SupersedesChainIdDetails> {
        match self
            .profile_extensions
            .get(&ProfileExtensionKind::SupersedesChainId)
        {
            Some(ProfileExtensionDetails::SupersedesChainId(details)) => Some(details),
            _ => None,
        }
    }

    pub(crate) fn identity_attestation_subject(&self) -> Option<&str> {
        match self
            .profile_extensions
            .get(&ProfileExtensionKind::IdentityAttestationSubject)
        {
            Some(ProfileExtensionDetails::IdentityAttestationSubject(subject)) => Some(subject),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SigningKeyEntry {
    pub(crate) public_key: [u8; 32],
    pub(crate) status: u64,
    pub(crate) valid_from: Option<TrellisTimestamp>,
    pub(crate) valid_to: Option<TrellisTimestamp>,
}

/// A reserved non-signing `KeyEntry` (Core §8.7 / ADR 0006).
///
/// Phase-1 verifiers track these so a signature attempt under a kid registered
/// as `tenant-root`, `scope`, `subject`, or `recovery` can be flagged with
/// `key_class_mismatch` (Core §8.7.3 step 4) rather than the generic
/// `unresolvable_manifest_kid` failure.
///
/// `valid_to` is captured for `subject`-class entries so a future Phase-1
/// `KeyBagEntry`-mediated `subject_wrap_after_valid_to` enforcement can run
/// without re-decoding the registry. Phase-1 `KeyBagEntry.recipient` is
/// opaque bytes (Core §9.4); ADR 0006 *Phase-1 runtime discipline* defers
/// recipient-to-`subject` kid binding to Phase-2+. The field is therefore
/// captured-but-unused at runtime today; see `tamper/025` for the wire
/// shape that tests this path.
#[derive(Clone, Debug)]
pub(crate) struct NonSigningKeyEntry {
    /// Class string from the registry entry's `kind` field, normalized so the
    /// legacy synonym `"wrap"` is mapped to `"subject"` per Core §8.7.6.
    pub(crate) class: String,
    /// Subject-class `valid_to` (per `SubjectKeyAttributes` in Core §8.7.2),
    /// captured for forward-compatible enforcement (see field-level doc above).
    /// `None` for non-`subject` classes and for `subject` rows with `valid_to = null`.
    #[allow(dead_code)]
    pub(crate) subject_valid_to: Option<TrellisTimestamp>,
}

#[derive(Clone, Debug)]
pub(crate) struct RegistryBindingInfo {
    pub(crate) digest_hex: String,
    pub(crate) bound_at_sequence: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct BoundRegistry {
    pub(crate) event_types: Vec<String>,
    pub(crate) classifications: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum PayloadRef {
    Inline(Vec<u8>),
    External,
}

#[derive(Clone, Debug)]
pub(crate) struct TransitionDetails {
    pub(crate) kind: TransitionKind,
    pub(crate) transition_id: String,
    pub(crate) from_state: String,
    pub(crate) to_state: String,
    pub(crate) declaration_digest: [u8; 32],
    pub(crate) attestation_classes: Vec<String>,
    /// Only populated for disclosure-profile transitions (Appendix A.5.2).
    /// Custody-model transitions derive their attestation rule from
    /// from_state→to_state custody-rank ordering instead (A.5.3 step 4).
    pub(crate) scope_change: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransitionKind {
    CustodyModel,
    DisclosureProfile,
}

impl TransitionKind {
    pub(crate) fn as_report_str(&self) -> &'static str {
        match self {
            TransitionKind::CustodyModel => "custody-model",
            TransitionKind::DisclosureProfile => "disclosure-profile",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AttachmentBindingDetails {
    pub(crate) attachment_id: String,
    pub(crate) slot_path: String,
    pub(crate) media_type: String,
    pub(crate) byte_length: u64,
    pub(crate) attachment_sha256: [u8; 32],
    pub(crate) payload_content_hash: [u8; 32],
    pub(crate) filename: Option<String>,
    pub(crate) prior_binding_hash: Option<[u8; 32]>,
}

/// Decoded `trellis.erasure-evidence.v1` payload (ADR 0005 §"Wire shape").
/// Carries the inputs needed for cross-event finalization (steps 5 / 8) and
/// the report-level fields surfaced through [`ErasureEvidenceOutcome`].
#[derive(Clone, Debug)]
pub(crate) struct ErasureEvidenceDetails {
    pub(crate) evidence_id: String,
    pub(crate) kid_destroyed: Vec<u8>,
    /// Wire `key_class` AFTER the `wrap` → `subject` normalization (Core
    /// §8.7.6 / ADR 0005 step 2). Stored as the normalized string so step 5
    /// / step 8 group reasoning compares apples to apples.
    pub(crate) norm_key_class: String,
    pub(crate) destroyed_at: TrellisTimestamp,
    pub(crate) cascade_scopes: Vec<String>,
    pub(crate) completion_mode: String,
    /// Phase-1 contract: every attestation row has structural shape
    /// (64-byte signature; valid `authority_class`). Crypto-verification of
    /// the Ed25519 signature itself is deferred to Phase-2+ alongside the
    /// posture-transition flow — see `TRANSITION_ATTESTATION_DOMAIN`.
    pub(crate) attestation_signatures_well_formed: bool,
    /// Reserved for the §10 outcome shape (per-class attestation reporting).
    /// The dual-attestation rule (Companion OC-143) is a SHOULD-grade
    /// per-deployment policy declared in the Posture Declaration; the
    /// Phase-1 verifier captures the classes for tooling but does not gate
    /// `integrity_verified` on count.
    #[allow(dead_code)]
    pub(crate) attestation_classes: Vec<String>,
    /// Subject-scope kind text (`per-subject` / `per-scope` / `per-tenant`
    /// / `deployment-wide`). Captured for the §10 outcome report; the
    /// cross-field shape rule (step 3) is enforced inline at decode time.
    #[allow(dead_code)]
    pub(crate) subject_scope_kind: String,
}

/// Decoded `trellis.certificate-of-completion.v1` payload (ADR 0007 §"Wire
/// shape"). Carries the inputs needed for cross-event finalization (step 5
/// signing-event resolution; step 6 temporal equivalence; step 7 response
/// hash) and the report-level fields surfaced through
/// [`CertificateOfCompletionOutcome`]. CDDL decode + chain-summary
/// invariants (steps 1 and 2) run in [`decode_certificate_payload`]; step 3
/// (attestation crypto) shape-checks at decode time and crypto-verification
/// is deferred to Phase 2+ — see [`TRANSITION_ATTESTATION_DOMAIN`].
#[derive(Clone, Debug)]
pub(crate) struct CertificateDetails {
    pub(crate) certificate_id: String,
    /// Reserved for §6.4 operator obligations; Phase-1 verifier captures the
    /// field but does not gate on its presence beyond the CDDL shape.
    #[allow(dead_code)]
    pub(crate) case_ref: Option<String>,
    pub(crate) completed_at: TrellisTimestamp,
    pub(crate) presentation_artifact: PresentationArtifactDetails,
    pub(crate) chain_summary: ChainSummaryDetails,
    /// `signing_events[i]` digests in workflow order.
    pub(crate) signing_events: Vec<[u8; 32]>,
    /// Opaque to Trellis verification per ADR 0007 §"Field semantics";
    /// captured for completeness, not gated.
    #[allow(dead_code)]
    pub(crate) workflow_ref: Option<String>,
    /// Phase-1 contract: every attestation row has structural shape
    /// (64-byte signature; valid `authority_class`). Crypto-verification
    /// of the Ed25519 signature itself is deferred to Phase-2+ alongside
    /// the posture-transition + erasure flows — see
    /// [`TRANSITION_ATTESTATION_DOMAIN`]. Maps to step-3 contract; surfaces
    /// via the existing `attestation_insufficient` failure code.
    pub(crate) attestation_signatures_well_formed: bool,
}

/// Decoded `PresentationArtifact` map (ADR 0007 §"Wire shape").
#[derive(Clone, Debug)]
pub(crate) struct PresentationArtifactDetails {
    pub(crate) content_hash: [u8; 32],
    pub(crate) media_type: String,
    /// Reserved for the §"Adversary model" artifact-swap detection extension;
    /// Phase-1 captures but does not gate beyond CDDL shape.
    #[allow(dead_code)]
    pub(crate) byte_length: u64,
    /// Step-4 attachment lineage resolution is parameterized on this id.
    pub(crate) attachment_id: String,
    /// Reserved for the optional template-rendering-drift stretch check
    /// (ADR 0007 §"Field semantics"); Phase-1 verifier captures but does not
    /// re-render.
    #[allow(dead_code)]
    pub(crate) template_id: Option<String>,
    /// Reserved for the optional template-rendering-drift stretch check;
    /// Phase-1 enforces the CDDL invariant that HTML media type carries a
    /// non-null template_hash but does not recompute.
    #[allow(dead_code)]
    pub(crate) template_hash: Option<[u8; 32]>,
}

/// Decoded `ChainSummary` map (ADR 0007 §"Wire shape").
#[derive(Clone, Debug)]
pub(crate) struct ChainSummaryDetails {
    pub(crate) signer_count: u64,
    /// Per-signer display rows; step 2 invariant
    /// `len(signer_display) == len(signing_events)` enforced at decode.
    pub(crate) signer_display: Vec<SignerDisplayDetails>,
    #[allow(dead_code)]
    pub(crate) response_ref: Option<[u8; 32]>,
    /// Wire `workflow_status` value; CDDL admits the four enum literals
    /// plus registered extension `tstr`. Phase-1 reference verifier
    /// admits any `tstr` shape; deep registry-membership rides
    /// `certificate_enum_extension_unknown` evolution alongside WOS
    /// signature-profile registry plumbing.
    #[allow(dead_code)]
    pub(crate) workflow_status: String,
    /// Wire `impact_level` value or null; same registry-deferral posture
    /// as `workflow_status`.
    #[allow(dead_code)]
    pub(crate) impact_level: Option<String>,
    /// Operator-asserted cross-check tag set; empty / absent means the
    /// default §"Verifier obligations" check set applies. Phase-1
    /// reference verifier admits any `tstr` and surfaces unknown tags via
    /// `certificate_covered_claim_unknown` evolution alongside the §19.1
    /// fixture corpus.
    #[allow(dead_code)]
    pub(crate) covered_claims: Vec<String>,
}

/// Decoded `trellis.user-content-attestation.v1` payload (ADR 0010 §"Wire
/// shape" / Core §28 CDDL `UserContentAttestationPayload`). Mirrors the
/// shape used by `trellis_py.verify.UserContentAttestationDetails`. The
/// fields land directly in [`UserContentAttestationOutcome`] after
/// cross-event finalization in [`finalize_user_content_attestations`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UserContentAttestationDetails {
    pub(crate) attestation_id: String,
    pub(crate) attested_event_hash: [u8; 32],
    pub(crate) attested_event_position: u64,
    pub(crate) attestor: String,
    /// `None` only when the deployment Posture Declaration in force at
    /// `attested_at` declares `admit_unverified_user_attestations: true`.
    /// Default REQUIRED non-null per ADR 0010 §"Field semantics"; step 4
    /// (identity resolution) gates on the resolved Posture Declaration
    /// field, surfacing `user_content_attestation_identity_required` when
    /// admission is missing.
    pub(crate) identity_attestation_ref: Option<[u8; 32]>,
    pub(crate) signing_intent: String,
    pub(crate) attested_at: TrellisTimestamp,
    /// 64-byte detached Ed25519 signature over `dCBOR([attestation_id,
    /// attested_event_hash, attested_event_position, attestor,
    /// identity_attestation_ref, signing_intent, attested_at])` under domain
    /// tag `trellis-user-content-attestation-v1` (Core §9.8). Decoder
    /// validates structural shape; crypto verification runs in finalize step 5.
    pub(crate) signature: [u8; 64],
    /// Core §8 KeyEntry kid (16 bytes; per the Rust-byte-authority
    /// reconciliation noted in Core §28 — the ADR 0010 prose draft used
    /// `tstr` informally but the canonical taxonomy is the 16-byte digest
    /// of `dCBOR(suite_id) || pubkey_raw`). Resolved against the
    /// signing-key registry in finalize step 6.
    pub(crate) signing_kid: Vec<u8>,
    /// Canonical preimage that step 5 hashes against
    /// `USER_CONTENT_ATTESTATION_DOMAIN`. Pre-computed at decode time so
    /// the finalize pass can re-verify without re-encoding.
    pub(crate) canonical_preimage: Vec<u8>,
    /// ADR 0010 §"Verifier obligations" step 2 deferred-failure marker.
    /// `Some(kind)` when the decoder detected an intra-payload-invariant
    /// failure (`user_content_attestation_intent_malformed` /
    /// `user_content_attestation_timestamp_mismatch`); `None` when step 2
    /// passed. Step 2 failures flip `integrity_verified = false` per ADR
    /// 0010 — they are NOT structure failures and MUST NOT flip
    /// `readability_verified`. The finalize pass raises the marker as an
    /// `event_failure` and skips remaining checks for the event.
    pub(crate) step_2_failure: Option<VerificationFailureKind>,
}

/// Decoded `SignerDisplayEntry` (ADR 0007 §"Wire shape").
#[derive(Clone, Debug)]
pub(crate) struct SignerDisplayDetails {
    #[allow(dead_code)]
    pub(crate) principal_ref: String,
    /// Operator-rendered display name; not strict-compared per ADR 0007
    /// §"Field semantics" (verifier surfaces gross mismatch only).
    #[allow(dead_code)]
    pub(crate) display_name: String,
    /// Operator-supplied display role; reserved for surfaced summary.
    #[allow(dead_code)]
    pub(crate) display_role: Option<String>,
    /// Step 6 inputs: MUST exactly equal the resolved SignatureAffirmation
    /// header `authored_at` for `signing_events[i]`.
    pub(crate) signed_at: TrellisTimestamp,
}

#[derive(Clone, Debug)]
pub(crate) struct AttachmentExportExtension {
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) inline_attachments: bool,
}

/// Decoded `SupersedesChainIdPayload` carried by
/// `EventPayload.extensions["trellis.supersedes-chain-id.v1"]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SupersedesChainIdDetails {
    pub(crate) chain_id: Vec<u8>,
    pub(crate) checkpoint_hash: [u8; 32],
}

/// Optional `trellis.export.supersession-graph.v1` manifest extension
/// (ADR 0066 / Core §18.3b).
#[derive(Clone, Debug)]
pub(crate) struct SupersessionGraphExportExtension {
    pub(crate) graph_digest: [u8; 32],
    pub(crate) predecessor_count: u64,
}

/// Optional `trellis.export.open-clocks.v1` manifest extension.
#[derive(Clone, Debug)]
pub(crate) struct OpenClocksExportExtension {
    pub(crate) open_clocks_digest: [u8; 32],
    pub(crate) open_clock_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenClockCatalog {
    pub(crate) sealed_at: TrellisTimestamp,
    pub(crate) open_clocks: Vec<OpenClockCatalogRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenClockCatalogRow {
    pub(crate) clock_id: String,
    pub(crate) clock_kind: String,
    pub(crate) computed_deadline: TrellisTimestamp,
    pub(crate) origin_event_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SupersessionGraphPredecessor {
    pub(crate) chain_id: Vec<u8>,
    pub(crate) checkpoint_hash: [u8; 32],
    pub(crate) bundle_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SupersessionGraph {
    pub(crate) head_chain_id: Vec<u8>,
    pub(crate) predecessors: Vec<SupersessionGraphPredecessor>,
}

#[derive(Clone, Debug)]
pub(crate) struct AttachmentManifestEntry {
    pub(crate) binding_event_hash: [u8; 32],
    pub(crate) attachment_id: String,
    pub(crate) slot_path: String,
    pub(crate) media_type: String,
    pub(crate) byte_length: u64,
    pub(crate) attachment_sha256: [u8; 32],
    pub(crate) payload_content_hash: [u8; 32],
    pub(crate) filename: Option<String>,
    pub(crate) prior_binding_hash: Option<[u8; 32]>,
}

/// Optional `trellis.export.erasure-evidence.v1` manifest extension (ADR 0005).
#[derive(Clone, Debug)]
pub(crate) struct ErasureEvidenceExportExtension {
    pub(crate) catalog_ref: String,
    pub(crate) catalog_digest: [u8; 32],
    pub(crate) entry_count: u64,
}

/// One row in `064-erasure-evidence.cbor` (ADR 0005 export manifest catalog).
#[derive(Clone, Debug)]
pub(crate) struct ErasureEvidenceCatalogEntryRow {
    pub(crate) canonical_event_hash: [u8; 32],
    pub(crate) evidence_id: String,
    pub(crate) kid_destroyed: [u8; 16],
    pub(crate) destroyed_at: TrellisTimestamp,
    pub(crate) completion_mode: String,
    pub(crate) cascade_scopes: Vec<String>,
    pub(crate) subject_scope_kind: String,
}

/// Optional `trellis.export.certificates-of-completion.v1` manifest extension
/// (ADR 0007 §"Export manifest catalog"). Mirror of
/// [`ErasureEvidenceExportExtension`].
#[derive(Clone, Debug)]
pub(crate) struct CertificateExportExtension {
    pub(crate) catalog_ref: String,
    pub(crate) catalog_digest: [u8; 32],
    pub(crate) entry_count: u64,
}

/// One row in `065-certificates-of-completion.cbor` (ADR 0007 §"Export
/// manifest catalog" — `CertificateOfCompletionCatalogEntry`). Mirrors
/// [`ErasureEvidenceCatalogEntryRow`]; binds canonical certificate event
/// metadata for auditor-UX cross-check.
#[derive(Clone, Debug)]
pub(crate) struct CertificateCatalogEntryRow {
    pub(crate) canonical_event_hash: [u8; 32],
    pub(crate) certificate_id: String,
    pub(crate) completed_at: TrellisTimestamp,
    pub(crate) signer_count: u64,
    pub(crate) media_type: String,
    pub(crate) attachment_id: String,
    pub(crate) workflow_status: String,
}

#[derive(Debug)]
/// Parsed export ZIP: keys are **relative** paths under a single root directory
/// (for example `000-manifest.cbor`), not full ZIP entry names.
///
/// Every committed export uses exactly one top-level directory; see
/// [`parse_export_zip`] for the layout contract.
pub(crate) struct ExportArchive {
    pub(crate) members: BTreeMap<String, Vec<u8>>,
}

pub(crate) struct VerifyEventSetOptions<'a> {
    pub(crate) non_signing_registry: Option<&'a BTreeMap<Vec<u8>, NonSigningKeyEntry>>,
    pub(crate) initial_posture_declaration: Option<&'a [u8]>,
    pub(crate) posture_declaration: Option<&'a [u8]>,
    pub(crate) classify_tamper: bool,
    pub(crate) expected_ledger_scope: Option<&'a [u8]>,
    pub(crate) payload_blobs: Option<&'a BTreeMap<[u8; 32], Vec<u8>>>,
    pub(crate) record_validator: &'a dyn crate::trellis::validator::RecordValidator,
}

/// Per-event chain summary used by ADR 0005 step 8 — the destroyed-kid
/// chain-consistency walk needs `authored_at`, the signing `kid`, every
/// `key_bag.entries[*].recipient`, and the canonical event hash for failure
/// localization.
#[derive(Clone, Debug)]
pub(crate) struct ChainEventSummary {
    /// Reserved for future step-8 localization where the chain index is the
    /// dominant audit dimension. Today step 8 localizes by canonical event
    /// hash (parallel to existing event_failures localization).
    #[allow(dead_code)]
    pub(crate) event_index: u64,
    pub(crate) authored_at: TrellisTimestamp,
    pub(crate) signing_kid: Vec<u8>,
    pub(crate) wrap_recipients: Vec<Vec<u8>>,
    pub(crate) canonical_event_hash: [u8; 32],
}
