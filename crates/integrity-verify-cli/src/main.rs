// Rust guideline compliant 2026-02-21
//! Standalone offline verifier CLI over [`integrity_verify::verify_universal`].
//!
//! Per the signature-wire convergence plan §12 O-4 + E-10, the verifier ships
//! as a distinct binary deliverable handed to judges, regulators, and partner
//! institutions. `trellis-cli` remains for envelope-only fixture operations;
//! this CLI is the general `verify <bundle.zip>` entrypoint.
//!
//! ## Bundle layout convention
//!
//! Bundles produced by `integrity-bundle` are deterministic ZIP archives
//! (STORED-only, fixed timestamps, sorted paths). This CLI reads every
//! `.cbor` entry and tries to decode it as a tagged COSE_Sign1 envelope —
//! entries that parse become events under [`VerifyEvent`]; entries that do
//! not parse remain in the bundle structural axis only. All entry paths
//! participate in [`BundleStructuralCheck`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

use integrity_verify::{ProfileRegistry, WOS_PROFILE_ID};

mod cli;
mod profile;
mod zip_reader;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    match cli::run(&args, &mut stdout, &mut stderr, &default_registry) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = std::io::Write::write_all(&mut stderr, message.as_bytes());
            let _ = std::io::Write::write_all(&mut stderr, b"\n");
            ExitCode::from(1)
        }
    }
}

/// Default profile registry constructor. Registers a permissive WOS profile
/// stub keyed by [`WOS_PROFILE_ID`] so envelopes carrying that profile route
/// to a verifier without forcing the CLI to ship the full WOS plugin yet.
///
/// **Scope note:** 4A.1 establishes the binary surface; the production WOS
/// `ProfileVerifier` lands when `trellis-verify-wos` is lifted into the
/// `integrity-stack/` profile-plugin tree. Until then, the registry routes
/// `WOS_PROFILE_ID` to a "structural ack" verifier and registers a default
/// route for envelopes that omit `profile_id`.
fn default_registry(profile_id: Option<u64>) -> ProfileRegistry {
    let mut registry = ProfileRegistry::new();
    let target = profile_id.unwrap_or(WOS_PROFILE_ID);
    registry.register(Box::new(profile::StructuralAckProfile::new(target)));
    registry.register_default(Box::new(profile::StructuralAckProfile::new(0)));
    registry
}
