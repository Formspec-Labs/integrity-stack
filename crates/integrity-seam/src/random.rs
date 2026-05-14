// Rust guideline compliant 2026-02-21

//! Entropy sources for sealing code.
//!
//! The trait keeps entropy mockable at call sites that need deterministic test
//! inputs while letting production code use operating-system randomness.

use rand_core::{OsRng, RngCore};
use std::error::Error;

/// Fills caller-owned buffers with cryptographically secure random bytes.
pub trait SecureRandom: Send + Sync {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    /// Returns an error when the backing entropy source cannot provide bytes.
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Reads cryptographically secure bytes from the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut rng = OsRng;
        rng.try_fill_bytes(dest)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
    }
}
