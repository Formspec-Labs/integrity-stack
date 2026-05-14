// Rust guideline compliant 2026-02-21

//! Shared sealing seams for integrity profiles.
//!
//! The crate starts with the entropy abstraction used by higher-level sealing
//! code. Later tasks add the byte-building and async sealing traits on the same
//! public surface.

pub mod random;
pub mod seam;

#[doc(inline)]
pub use random::{OsSecureRandom, SecureRandom};
#[doc(inline)]
pub use seam::{
    AsyncSealer, KidInput, SealError, SealInput, SealInputBuilder, SealRequest, SealedEnvelope,
    default_seal_input,
};
