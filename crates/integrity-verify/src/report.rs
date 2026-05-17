// Rust guideline compliant 2026-02-21
//! Universal verification report shape.
//!
//! [`SubstrateTier`] reports the highest substrate capability the
//! verifier observed in this run — see the convergence plan §2.4
//! (L0..L3 ladder). Profile-specific outcome rows live in
//! [`crate::ProfileVerificationResult`], not on this struct.

use crate::bundle::BundleStructuralFinding;
use crate::canonical::CanonicalFinding;
use crate::chain::ChainFinding;
use crate::cose::CoseEnvelopeFinding;
use crate::profile::ProfileVerificationResult;

/// Substrate capability tier observed during verification.
///
/// Closed ladder per the signature-wire convergence plan §2.4:
///
/// | Tier | What the verifier observed |
/// |------|----------------------------|
/// | `L0` | Event bag; per-event envelope shape / signature only. |
/// | `L1` | `L0` + chain-hash continuity over linked events. |
/// | `L2` | `L1` + deterministic bundle structural check (signed-checkpoint, offline-verifiable bundle shape). |
/// | `L3` | `L2` + external witness (transparency log, Rekor, SCITT, C2PA sidecar). |
///
/// The universal verifier can attest up to `L2` from the bytes it sees.
/// `L3` requires out-of-band witness evidence supplied by a caller and is
/// reported only when an external witness attestation has been verified
/// upstream and surfaced through a profile verifier or future witness
/// adapter. **Cases (per the D-1 / E-5 commitment) require `L2` or
/// higher.** Below `L2` the system has case *operations* but not case
/// *integrity claims*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubstrateTier {
    /// Per-event envelope shape / signature only.
    L0,
    /// `L0` + chain-hash continuity.
    L1,
    /// `L1` + deterministic bundle structural check.
    L2,
    /// `L2` + external witness.
    L3,
}

impl SubstrateTier {
    /// Returns the schema-stable string token for this tier.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

/// One signed event in a [`VerifyBundleInput`].
pub struct VerifyEvent<'a> {
    /// The tagged COSE_Sign1 bytes.
    pub sign1_bytes: &'a [u8],

    /// Optional Ed25519 public key for signature verification. When
    /// `None`, the universal phase decodes the envelope and checks
    /// structural shape but skips signature verification.
    pub public_key: Option<[u8; 32]>,

    /// Optional detached payload. Required when the envelope's payload
    /// field is `null`; ignored when the envelope embeds its payload.
    pub detached_payload: Option<&'a [u8]>,
}

/// Optional canonical-bytes digest check the caller wants the universal
/// phase to perform. The shape matches
/// [`integrity_canonical::verify_signed_payload_digest`].
pub struct CanonicalDigestCheck<'a> {
    /// Canonical-bytes representation (already JCS-canonicalized).
    pub bytes: &'a [u8],

    /// The declared digest algorithm token (e.g. `"sha-256"`).
    pub algorithm_token: &'a str,

    /// The declared lowercase-hex digest value.
    pub declared_digest: &'a str,
}

/// Input bundle for [`crate::verify_universal`].
///
/// Each field is optional so callers can run a subset of universal
/// checks. `events` is the primary surface; `bundle_entries`,
/// `chain_events`, and `canonical_digest_check` opt-in to the bundle /
/// chain / canonical checks respectively.
pub struct VerifyBundleInput<'a> {
    /// COSE_Sign1 events under verification.
    pub events: &'a [VerifyEvent<'a>],

    /// Optional deterministic-bundle entries (sorted-path check).
    pub bundle_entries: Option<&'a [BundleEntryView<'a>]>,

    /// Optional chain events for hash-continuity verification.
    pub chain_events: Option<&'a [ChainEventView]>,

    /// Optional canonical-bytes digest check.
    pub canonical_digest_check: Option<&'a CanonicalDigestCheck<'a>>,
}

/// Read-only view of one deterministic-bundle entry. The universal phase
/// only inspects the path; payload bytes are profile-flavored.
pub struct BundleEntryView<'a> {
    pub path: &'a str,
}

/// Chain-event view used for hash-continuity verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEventView {
    /// Sequence number from the event envelope.
    pub sequence: u64,
    /// Canonical event hash for this event.
    pub canonical_event_hash: [u8; 32],
    /// Previous canonical event hash, if any. `None` is permitted only
    /// for sequence 0.
    pub previous_hash: Option<[u8; 32]>,
}

/// Universal-phase failure kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UniversalFailureKind {
    /// COSE_Sign1 bytes did not decode under RFC 9052.
    MalformedEnvelope,
    /// Required protected-header label was missing.
    MissingProtectedHeader,
    /// Algorithm / suite combination is not recognized.
    UnsupportedAlgorithm,
    /// Ed25519 signature failed verification.
    SignatureInvalid,
    /// No [`crate::ProfileVerifier`] is registered for semantic checks.
    MissingProfileVerifier,
    /// JCS canonical-bytes digest did not match the declared digest.
    CanonicalDigestMismatch,
    /// Chain-hash continuity violated (prev_hash, ordering).
    ChainContinuityViolation,
    /// Deterministic-bundle structural rule violated (sort, duplicates).
    BundleStructuralViolation,
}

impl UniversalFailureKind {
    /// Returns the schema-stable string token for this failure kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedEnvelope => "malformed_envelope",
            Self::MissingProtectedHeader => "missing_protected_header",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::SignatureInvalid => "signature_invalid",
            Self::MissingProfileVerifier => "missing_profile_verifier",
            Self::CanonicalDigestMismatch => "canonical_digest_mismatch",
            Self::ChainContinuityViolation => "chain_continuity_violation",
            Self::BundleStructuralViolation => "bundle_structural_violation",
        }
    }
}

/// One failure surfaced by the universal phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniversalFailure {
    pub kind: UniversalFailureKind,
    /// Index into [`VerifyBundleInput::events`] when failure is event-scoped;
    /// `usize::MAX` for bundle / canonical / chain-level failures.
    pub event_index: usize,
    pub message: String,
}

impl UniversalFailure {
    /// Creates a universal failure entry.
    #[must_use]
    pub fn new(kind: UniversalFailureKind, event_index: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            event_index,
            message: message.into(),
        }
    }

    /// Builds a bundle / canonical / chain-level failure (no event index).
    #[must_use]
    pub fn scope_wide(kind: UniversalFailureKind, message: impl Into<String>) -> Self {
        Self::new(kind, usize::MAX, message)
    }
}

/// Universal verification report.
///
/// The struct is intentionally non-exhaustive in spirit — additional
/// universal report rows (deterministic bundle outcomes, canonical-digest
/// outcomes, chain continuity) are kept as `Vec` so adding new universal
/// phases does not change the shape.
///
/// `substrate_tier: Option<SubstrateTier>` is set by
/// [`Self::recompute_flags`] to the highest substrate-capability tier the
/// verifier could attest from the bytes it observed. `None` is reported
/// when no events / chains / bundles were supplied (vacuous run) OR when a
/// universal failure prevented any tier from being reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerificationReport {
    /// Whether every universal check passed.
    pub universal_verified: bool,
    /// Whether every registered profile verifier reported success.
    pub profile_verified: bool,
    /// Set when a deterministic-bundle structural check ran.
    pub bundle_checked: bool,
    /// Set when chain-continuity verification ran.
    pub chain_checked: bool,
    /// Set when a canonical-bytes digest verification ran.
    pub canonical_checked: bool,

    /// Highest substrate-capability tier observed during this verification
    /// run (closed `L0..L3` ladder per CP §2.4). See [`SubstrateTier`].
    /// `None` means the verifier could not attest to any tier (vacuous
    /// input or universal failure).
    pub substrate_tier: Option<SubstrateTier>,

    /// Per-event envelope-shape findings.
    pub envelope_findings: Vec<CoseEnvelopeFinding>,
    /// Bundle-level structural findings.
    pub bundle_findings: Vec<BundleStructuralFinding>,
    /// Chain-continuity findings.
    pub chain_findings: Vec<ChainFinding>,
    /// Canonical-bytes digest findings.
    pub canonical_findings: Vec<CanonicalFinding>,
    /// Universal-phase failures (event-scoped or scope-wide).
    pub universal_failures: Vec<UniversalFailure>,
    /// Profile-verifier outcomes — one row per dispatched event.
    pub profile_results: Vec<ProfileVerificationResult>,

    /// Free-text warnings useful for operator reporting.
    pub warnings: Vec<String>,
}

impl VerificationReport {
    /// Creates an empty universal verification report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recomputes the boolean roll-up flags from the contained
    /// findings / failures vectors. Also recomputes [`Self::substrate_tier`]
    /// to the highest tier the verifier observed. Idempotent.
    pub fn recompute_flags(&mut self) {
        let envelope_clean = self.envelope_findings.iter().all(|f| f.is_advisory());
        let bundle_clean = self.bundle_findings.is_empty();
        let chain_clean = self.chain_findings.is_empty();
        let canonical_clean = self.canonical_findings.is_empty();
        let no_failures = self.universal_failures.is_empty();

        self.universal_verified =
            envelope_clean && bundle_clean && chain_clean && canonical_clean && no_failures;
        self.profile_verified = self.profile_results.iter().all(|r| r.verified);
        self.substrate_tier =
            self.derive_substrate_tier(envelope_clean, chain_clean, bundle_clean, no_failures);
    }

    /// Derives the highest substrate-capability tier the verifier could
    /// attest from the observed signals. The universal phase attests up
    /// to `L2`; `L3` requires an external-witness signal that must be
    /// supplied out-of-band (a future witness-adapter sets the field
    /// directly, after which a subsequent `recompute_flags` call should
    /// not be issued — or the adapter sets it after the recompute).
    fn derive_substrate_tier(
        &self,
        envelope_clean: bool,
        chain_clean: bool,
        bundle_clean: bool,
        no_failures: bool,
    ) -> Option<SubstrateTier> {
        let envelope_seen = !self.envelope_findings.is_empty()
            || !self.profile_results.is_empty()
            || self
                .universal_failures
                .iter()
                .any(|f| f.event_index != usize::MAX);

        if !envelope_seen {
            return None;
        }

        if !envelope_clean || !no_failures {
            return None;
        }

        let mut tier = SubstrateTier::L0;
        if self.chain_checked && chain_clean {
            tier = SubstrateTier::L1;
            if self.bundle_checked && bundle_clean {
                tier = SubstrateTier::L2;
            }
        }
        Some(tier)
    }
}
