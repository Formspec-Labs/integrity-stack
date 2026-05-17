// Rust guideline compliant 2026-02-21
//! Universal integrity verification phase.
//!
//! This crate owns the *universal* verification phase shared by every
//! integrity profile: COSE_Sign1 structural checks, Ed25519 signature
//! verification, JCS canonical-bytes verification, chain-hash continuity,
//! deterministic-bundle structural checks, and explicit handoff to a default
//! profile verifier.
//!
//! Profile semantics — WOS event vocabularies, Formspec response shapes,
//! Trellis posture transitions, FactsTier overlays — live in profile
//! crates that implement [`ProfileVerifier`] and register against a
//! [`ProfileRegistry`]. The dispatcher here is structural only.
//!
//! ## Surface
//!
//! - [`VerificationReport`] — universal-only report. Profile plugins
//!   contribute `ProfileVerificationResult` rows via the registry.
//! - [`verify_universal`] — top-level entry. Iterates a [`VerifyBundleInput`],
//!   runs universal checks, dispatches to registered profile verifiers.
//! - [`ProfileVerifier`] / [`ProfileRegistry`] — plugin surface.
//! - [`cose`] module — universal COSE_Sign1 structural checks.
//! - [`canonical`] module — JCS canonical-bytes verification.
//! - [`bundle`] module — deterministic-bundle structural checks.
//! - [`chain`] module — chain-hash continuity over [`IntegrityEvent`].

#![forbid(unsafe_code)]

pub mod bundle;
pub mod canonical;
pub mod chain;
pub mod cose;
pub mod profile;
pub mod report;
pub mod trellis;

#[cfg(test)]
mod tests;

pub use bundle::{BundleStructuralCheck, BundleStructuralFinding};
pub use canonical::{CanonicalCheck, CanonicalFinding};
pub use chain::{ChainContinuityCheck, ChainFinding};
pub use cose::{CoseEnvelopeCheck, CoseEnvelopeFinding};
pub use profile::{
    ProfileDispatchError, ProfileRegistry, ProfileVerificationResult, ProfileVerifier,
};
pub use report::{
    BundleEntryView, CanonicalDigestCheck, ChainEventView, SubstrateTier, UniversalFailure,
    UniversalFailureKind, VerificationReport, VerifyBundleInput, VerifyEvent,
};

use integrity_cose::{sig_structure_bytes, verify_ed25519_signature};

/// Top-level universal verifier entry.
///
/// Iterates the supplied [`VerifyBundleInput`], runs every universal check
/// (envelope shape, signature, chain continuity, JCS digest where
/// declared, bundle structural ordering), then dispatches each event to
/// the registry's explicit default [`ProfileVerifier`]. Missing defaults
/// produce named universal failures rather than hard aborting so the report
/// can record every envelope's outcome.
pub fn verify_universal(
    input: &VerifyBundleInput<'_>,
    registry: &ProfileRegistry,
) -> VerificationReport {
    let mut report = VerificationReport::new();

    if let Some(bundle_entries) = input.bundle_entries {
        let bundle_check = BundleStructuralCheck::run(bundle_entries);
        for finding in bundle_check.findings {
            report.bundle_findings.push(finding);
        }
        report.bundle_checked = true;
    }

    for (index, event) in input.events.iter().enumerate() {
        let envelope_check = match CoseEnvelopeCheck::run(event.sign1_bytes) {
            Ok(check) => check,
            Err(error) => {
                report.universal_failures.push(UniversalFailure::new(
                    UniversalFailureKind::MalformedEnvelope,
                    index,
                    error.to_string(),
                ));
                continue;
            }
        };
        report.envelope_findings.extend(envelope_check.findings);
        let decoded = envelope_check.envelope;

        if let Some(public_key) = event.public_key
            && let Some(payload) = decoded.resolve_payload(event.detached_payload).ok()
        {
            let sig_struct = sig_structure_bytes(decoded.protected_header(), payload);
            let signature: Result<[u8; 64], _> = decoded.signature().try_into();
            match signature {
                Ok(sig) => {
                    if !verify_ed25519_signature(public_key, &sig_struct, sig) {
                        report.universal_failures.push(UniversalFailure::new(
                            UniversalFailureKind::SignatureInvalid,
                            index,
                            "Ed25519 signature did not verify against the supplied public key",
                        ));
                    }
                }
                Err(_) => {
                    report.universal_failures.push(UniversalFailure::new(
                        UniversalFailureKind::SignatureInvalid,
                        index,
                        "signature is not 64 bytes",
                    ));
                }
            }
        }

        match registry.lookup_required() {
            Ok(verifier) => {
                let payload = decoded.resolve_payload(event.detached_payload).ok();
                let outcome = verifier
                    .verify_profile_record(payload.unwrap_or_default(), decoded.protected_header());
                report.profile_results.push(outcome);
            }
            Err(ProfileDispatchError::MissingDefaultVerifier) => {
                report.universal_failures.push(UniversalFailure::new(
                    UniversalFailureKind::MissingProfileVerifier,
                    index,
                    ProfileDispatchError::MissingDefaultVerifier.to_string(),
                ));
            }
        }
    }

    if let Some(chain_events) = input.chain_events {
        let chain_check = ChainContinuityCheck::run(chain_events);
        for finding in chain_check.findings {
            report.chain_findings.push(finding);
        }
        report.chain_checked = true;
    }

    if let Some(digest) = input.canonical_digest_check {
        let canonical_check = CanonicalCheck::run(digest);
        for finding in canonical_check.findings {
            report.canonical_findings.push(finding);
        }
        report.canonical_checked = true;
    }

    report.recompute_flags();
    report
}

// Re-exports used downstream so profile-plugin crates don't have to
// re-discover the COSE primitive crate.
pub use integrity_cose::{
    COSE_LABEL_ALG, COSE_LABEL_ARTIFACT_TYPE, COSE_LABEL_KID, COSE_LABEL_METHOD_URI,
    COSE_LABEL_SUITE_ID, CoseError, CoseSign1, SUITE_ID_PHASE_1,
    decode_cose_sign1 as decode_cose_envelope,
};
