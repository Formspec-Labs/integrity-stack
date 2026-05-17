// Rust guideline compliant 2026-02-21
//! Profile plugin surface for the universal verifier.
//!
//! The ADR 0109 surface split removes protected-header integer dispatch from
//! universal verification. The universal verifier now routes records only to
//! an explicitly configured default profile verifier. Consumer-owned method
//! dispatch lives in `integrity-cose` through signed `method_uri` values, and
//! Trellis substrate semantic dispatch lives in signed event payloads.

use std::fmt::{Display, Formatter};

/// Outcome row returned by one profile verifier per dispatched event.
///
/// Profile crates may extend this via the `details` field, which is an
/// opaque byte slot the profile crate owns. The universal phase does not
/// interpret `details` — it is reported verbatim to operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileVerificationResult {
    /// Stable identifier for the verifier that handled this event.
    pub verifier_id: String,
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
    pub fn verified(verifier_id: impl Into<String>, verdict: impl Into<String>) -> Self {
        Self {
            verifier_id: verifier_id.into(),
            verdict: verdict.into(),
            verified: true,
            findings: Vec::new(),
            details: None,
        }
    }

    /// Convenience constructor for a failed verdict.
    #[must_use]
    pub fn failed(
        verifier_id: impl Into<String>,
        verdict: impl Into<String>,
        findings: Vec<String>,
    ) -> Self {
        Self {
            verifier_id: verifier_id.into(),
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
    /// Returns the stable identifier for this verifier.
    fn verifier_id(&self) -> &str;

    /// Verifies one profile-flavored payload.
    ///
    /// The universal phase has already verified envelope shape and
    /// signature when a public key was supplied. The verifier inspects
    /// `payload_bytes` and decides whether the payload is valid for this
    /// profile.
    fn verify_profile_record(
        &self,
        payload_bytes: &[u8],
        protected_header_bytes: &[u8],
    ) -> ProfileVerificationResult;
}

/// Error returned when explicit dispatch cannot proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileDispatchError {
    /// The caller supplied no default verifier for semantic profile checks.
    MissingDefaultVerifier,
}

impl Display for ProfileDispatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDefaultVerifier => f.write_str("no default ProfileVerifier is registered"),
        }
    }
}

impl std::error::Error for ProfileDispatchError {}

/// Profile-verifier registry.
///
/// Register one default verifier explicitly via [`Self::register_default`].
/// The older [`Self::register`] method is retained as a convenience alias for
/// callers that already name their verifier object, but it no longer creates
/// an ID-keyed dispatch table.
#[derive(Default)]
pub struct ProfileRegistry {
    default_verifier: Option<Box<dyn ProfileVerifier>>,
}

impl ProfileRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the verifier as the default semantic profile checker.
    pub fn register(&mut self, verifier: Box<dyn ProfileVerifier>) {
        self.default_verifier = Some(verifier);
    }

    /// Registers the verifier as the default semantic profile checker.
    pub fn register_default(&mut self, verifier: Box<dyn ProfileVerifier>) {
        self.default_verifier = Some(verifier);
    }

    /// Looks up the configured default verifier.
    #[must_use]
    pub fn lookup(&self) -> Option<&dyn ProfileVerifier> {
        self.default_verifier.as_deref()
    }

    /// Returns the configured default verifier or a named error.
    pub fn lookup_required(&self) -> Result<&dyn ProfileVerifier, ProfileDispatchError> {
        self.default_verifier
            .as_deref()
            .ok_or(ProfileDispatchError::MissingDefaultVerifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerifier;

    impl ProfileVerifier for TestVerifier {
        fn verifier_id(&self) -> &str {
            "test"
        }

        fn verify_profile_record(&self, _: &[u8], _: &[u8]) -> ProfileVerificationResult {
            ProfileVerificationResult::verified(self.verifier_id(), "ok")
        }
    }

    #[test]
    fn registry_routes_to_default_verifier() {
        let mut registry = ProfileRegistry::new();
        registry.register_default(Box::new(TestVerifier));

        let verifier = registry.lookup_required().expect("default verifier");

        assert_eq!(verifier.verifier_id(), "test");
    }

    #[test]
    fn missing_default_verifier_returns_named_error() {
        let registry = ProfileRegistry::new();
        let error = match registry.lookup_required() {
            Ok(_) => panic!("missing default must reject"),
            Err(error) => error,
        };

        assert_eq!(error, ProfileDispatchError::MissingDefaultVerifier);
    }
}
