// Rust guideline compliant 2026-02-21
//! Profile plugin surface for the universal verifier.
//!
//! Profile verifiers register against a [`ProfileRegistry`] keyed by the
//! envelope's `profile_id`. The dispatcher in [`crate::verify_universal`]
//! looks up the verifier per event and hands it the decoded
//! payload bytes plus the protected-header bytes. Profile crates own
//! the decode and any cross-event finalization.
//!
//! **Dispatcher contract.** Explicit composition only — callers
//! construct a [`ProfileRegistry`] and register verifiers by hand
//! (`registry.register(Box::new(MyProfileVerifier))`). No `inventory`
//! crate, no auto-discovery, no implicit registration via build script
//! or link-time magic. Known `profile_id` routes through
//! [`ProfileRegistry::lookup_required`] to its registered verifier;
//! unknown `profile_id` returns a [`ProfileDispatchError::UnknownProfileId`]
//! named error, which the universal phase folds into the report as a
//! [`crate::report::UniversalFailureKind::UnknownProfileId`] failure. An
//! omitted `profile_id` without an explicit default verifier similarly reports
//! [`crate::report::UniversalFailureKind::MissingProfileIdNoDefault`].
//!
//! Per the convergence plan §12 O-2 and UWU-1, the stack profile_id
//! allocations are [`WOS_PROFILE_ID`] and [`FORMSPEC_PROFILE_ID`].

use std::collections::HashMap;
use std::fmt::{Display, Formatter};

/// `profile_id` value for the WOS profile.
///
/// Allocated per the convergence plan §12 O-2 alongside the COSE
/// protected-header label `COSE_LABEL_PROFILE_ID = -65539`. The value
/// here is the profile-identity payload that label carries — distinct
/// from the label itself. Mirrored at
/// `workspec-server/crates/wos-server/src/http/case_event_custody.rs`
/// (server-side composition).
pub const WOS_PROFILE_ID: u64 = 1;

/// `profile_id` value for the Formspec authored-signature profile.
///
/// Allocated by UWU-1 for COSE protected-header dispatch under label
/// `COSE_LABEL_PROFILE_ID = -65539`. The value here is distinct from the
/// protected-header label itself.
pub const FORMSPEC_PROFILE_ID: u64 = 2;

/// Outcome row returned by one profile verifier per dispatched event.
///
/// Profile crates may extend this via the `details` field, which is an
/// opaque byte slot the profile crate owns. The universal phase does not
/// interpret `details` — it is reported verbatim to operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileVerificationResult {
    /// The `profile_id` that handled this event.
    pub profile_id: u64,
    /// Schema-stable profile-supplied verdict token.
    pub verdict: String,
    /// `true` when the profile verifier reports success.
    pub verified: bool,
    /// Free-text findings the profile wants surfaced to operators.
    pub findings: Vec<String>,
    /// Opaque profile-owned detail bytes. Profile crates may serialize
    /// richer per-profile reports here (CBOR / JSON / framed).
    pub details: Option<Vec<u8>>,
}

impl ProfileVerificationResult {
    /// Convenience constructor for "verified, no findings".
    #[must_use]
    pub fn verified(profile_id: u64, verdict: impl Into<String>) -> Self {
        Self {
            profile_id,
            verdict: verdict.into(),
            verified: true,
            findings: Vec::new(),
            details: None,
        }
    }

    /// Convenience constructor for a failed verdict.
    #[must_use]
    pub fn failed(profile_id: u64, verdict: impl Into<String>, findings: Vec<String>) -> Self {
        Self {
            profile_id,
            verdict: verdict.into(),
            verified: false,
            findings,
            details: None,
        }
    }
}

/// Profile-plugin trait implemented by per-profile verifier crates.
///
/// Implementations are stateless from the universal phase's perspective;
/// any cross-event state lives inside the implementation.
pub trait ProfileVerifier: Send + Sync {
    /// Returns the `profile_id` this verifier handles.
    fn profile_id(&self) -> u64;

    /// Verifies one profile-flavored payload.
    ///
    /// The universal phase has already verified envelope shape and
    /// signature (if a public key was supplied). The verifier inspects
    /// `payload_bytes` (the resolved COSE payload) and decides whether
    /// the payload is a valid record for this profile.
    fn verify_profile_record(
        &self,
        envelope_profile_id: u64,
        payload_bytes: &[u8],
        protected_header_bytes: &[u8],
    ) -> ProfileVerificationResult;
}

/// Error returned by [`ProfileRegistry::lookup_required`] when explicit
/// dispatch cannot proceed. The universal phase folds these into the
/// report as named universal failures, but callers driving dispatch directly
/// (e.g., a profile adapter or a CLI) receive the named variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileDispatchError {
    /// No verifier registered for the supplied `profile_id`. Carries the
    /// rejected id for operator diagnostics.
    UnknownProfileId(u64),
    /// The envelope carries no `profile_id` and no default verifier is
    /// registered. Returned for envelopes from the Phase-1 suite_id-only
    /// era when the registry has no default route.
    MissingProfileIdNoDefault,
}

impl Display for ProfileDispatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProfileId(id) => {
                write!(f, "no ProfileVerifier registered for profile_id={id}")
            }
            Self::MissingProfileIdNoDefault => write!(
                f,
                "envelope has no profile_id and no default verifier is registered"
            ),
        }
    }
}

impl std::error::Error for ProfileDispatchError {}

/// Profile-verifier registry. Maps `profile_id -> Box<dyn ProfileVerifier>`.
///
/// Register verifiers manually via [`Self::register`]; route dispatch
/// through [`Self::lookup_required`] for named-error rejection on unknown
/// `profile_id`.
#[derive(Default)]
pub struct ProfileRegistry {
    by_profile_id: HashMap<u64, Box<dyn ProfileVerifier>>,
    default_verifier: Option<Box<dyn ProfileVerifier>>,
}

impl ProfileRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a profile verifier under the verifier's declared
    /// `profile_id`.
    pub fn register(&mut self, verifier: Box<dyn ProfileVerifier>) {
        let profile_id = verifier.profile_id();
        self.by_profile_id.insert(profile_id, verifier);
    }

    /// Registers the verifier to handle envelopes whose `profile_id`
    /// header is absent (suite_id-only envelopes from the Phase-1
    /// envelope era).
    pub fn register_default(&mut self, verifier: Box<dyn ProfileVerifier>) {
        self.default_verifier = Some(verifier);
    }

    /// Looks up the registered verifier for an envelope's `profile_id`.
    /// `None` falls back to the default verifier if one is registered.
    #[must_use]
    pub fn lookup(&self, profile_id: Option<u64>) -> Option<&dyn ProfileVerifier> {
        match profile_id {
            Some(id) => self.by_profile_id.get(&id).map(|b| b.as_ref()),
            None => self.default_verifier.as_deref(),
        }
    }

    /// Explicit-composition dispatch: returns the registered verifier for
    /// `profile_id` or a named [`ProfileDispatchError`]. Callers driving
    /// the dispatcher directly (outside [`crate::verify_universal`]) use
    /// this to surface unknown-profile rejections as typed errors rather
    /// than report-folded failures.
    ///
    /// The lookup is explicit-composition only — the caller assembled
    /// the registry. No `inventory` magic, no auto-discovery. Unknown
    /// `profile_id` always rejects with a named error.
    pub fn lookup_required(
        &self,
        profile_id: Option<u64>,
    ) -> Result<&dyn ProfileVerifier, ProfileDispatchError> {
        match profile_id {
            Some(id) => self
                .by_profile_id
                .get(&id)
                .map(|b| b.as_ref())
                .ok_or(ProfileDispatchError::UnknownProfileId(id)),
            None => self
                .default_verifier
                .as_deref()
                .ok_or(ProfileDispatchError::MissingProfileIdNoDefault),
        }
    }

    /// Returns the registered `profile_id` set in insertion-independent
    /// (sorted ascending) order. Useful for diagnostics.
    pub fn registered_profile_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.by_profile_id.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerifier {
        profile_id: u64,
    }
    impl ProfileVerifier for TestVerifier {
        fn profile_id(&self) -> u64 {
            self.profile_id
        }
        fn verify_profile_record(&self, _: u64, _: &[u8], _: &[u8]) -> ProfileVerificationResult {
            ProfileVerificationResult::verified(self.profile_id, "ok")
        }
    }

    #[test]
    fn registry_dispatches_by_profile_id() {
        let mut registry = ProfileRegistry::new();
        registry.register(Box::new(TestVerifier { profile_id: 1 }));
        registry.register(Box::new(TestVerifier { profile_id: 7 }));

        assert!(registry.lookup(Some(1)).is_some());
        assert!(registry.lookup(Some(7)).is_some());
        assert!(registry.lookup(Some(99)).is_none());
        assert_eq!(registry.registered_profile_ids(), vec![1, 7]);
    }

    #[test]
    fn stack_profile_ids_are_allocated_without_collision() {
        assert_eq!(WOS_PROFILE_ID, 1);
        assert_eq!(FORMSPEC_PROFILE_ID, 2);
        assert_ne!(WOS_PROFILE_ID, FORMSPEC_PROFILE_ID);
    }

    #[test]
    fn registry_falls_back_to_default() {
        let mut registry = ProfileRegistry::new();
        registry.register_default(Box::new(TestVerifier { profile_id: 0 }));
        assert!(registry.lookup(None).is_some());
    }

    #[test]
    fn unknown_profile_id_lookup_returns_none() {
        let registry = ProfileRegistry::new();
        assert!(registry.lookup(Some(42)).is_none());
    }
}
