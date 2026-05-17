// Rust guideline compliant 2026-02-21
//! Standalone offline verifier CLI over universal and Trellis/WOS export checks.
//!
//! Per the signature-wire convergence plan §12 O-4 + E-10, the verifier ships
//! as a distinct binary deliverable handed to judges, regulators, and partner
//! institutions. The generic `verify <bundle.zip>` command runs the universal
//! phase only; `verify-export <bundle.zip>` runs the production Trellis/WOS
//! export verifier.
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

use integrity_verify::ProfileRegistry;

mod cli;

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

fn default_registry() -> ProfileRegistry {
    ProfileRegistry::new()
}
