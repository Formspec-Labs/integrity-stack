// Rust guideline compliant 2026-02-21

//! Shared sealing seams for integrity profiles.
//!
//! The crate starts with the entropy abstraction used by higher-level sealing
//! code. Later tasks add the byte-building and async sealing traits on the same
//! public surface.

pub mod random;

#[doc(inline)]
pub use random::{OsSecureRandom, SecureRandom};
