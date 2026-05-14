// Rust guideline compliant 2026-02-21
//! Minimal profile-verifier shim used by the CLI until the `trellis-verify-wos`
//! lift lands its production WOS profile plugin in `integrity-stack/`.
//!
//! [`StructuralAckProfile`] simply acknowledges that the universal phase
//! validated the envelope's structural shape and routed dispatch to a
//! registered verifier. It does NOT validate WOS event-vocabulary semantics
//! — that work belongs to the per-profile plugin (Track 4A.2 / future).

use integrity_verify::{ProfileVerificationResult, ProfileVerifier};

/// Structural-acknowledgement profile verifier.
pub struct StructuralAckProfile {
    profile_id: u64,
}

impl StructuralAckProfile {
    /// Creates a structural-ack verifier registered against `profile_id`.
    #[must_use]
    pub fn new(profile_id: u64) -> Self {
        Self { profile_id }
    }
}

impl ProfileVerifier for StructuralAckProfile {
    fn profile_id(&self) -> u64 {
        self.profile_id
    }

    fn verify_profile_record(
        &self,
        envelope_profile_id: u64,
        _payload_bytes: &[u8],
        _protected_header_bytes: &[u8],
    ) -> ProfileVerificationResult {
        ProfileVerificationResult::verified(envelope_profile_id, "structural-ack")
    }
}
