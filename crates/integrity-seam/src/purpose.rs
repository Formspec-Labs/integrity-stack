// Rust guideline compliant 2026-02-21

//! One signing port, one key per purpose (ADR 0169).
//!
//! Every signature the stack makes goes through [`PurposeSigner`]. A signer holds one key per
//! [`Purpose`]: a current key plus the previous public key, so a rotation never strands a
//! signature. The caller passes the tenant scope key beside the purpose. Default adapters ignore
//! it; an adapter that holds one key per scope (HKDF in memory, one KMS key per tenant) can be
//! installed without touching callers.
//!
//! The port signs bytes a format has already prepared, such as a COSE `Sig_structure` or a JWS
//! signing input. Formats keep their own encoders. Ed25519 itself lives in `integrity-cose`,
//! which supplies the key-file adapter.

use std::fmt;

use async_trait::async_trait;

/// Names what a signing key is for. Closed over every signer in the stack (ADR 0169 section 1.1).
///
/// A signer added later adds its variant here, so a key can never be reused across purposes by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Purpose {
    /// Issuer JWT of an SD-JWT response attestation (ADR 0166 section 4).
    Attestation,
    /// The formspec e-signature seal.
    Seal,
    /// The delegated Response signature.
    DelegatedResponse,
    /// Export grants (ADR 0164).
    ExportGrant,
    /// WOS provenance (WS-043).
    Runtime,
    /// Trellis events and checkpoints.
    Ledger,
    /// Trellis export manifests.
    Manifest,
}

impl Purpose {
    /// Returns the stable lowercase label used in configuration and diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::Seal => "seal",
            Self::DelegatedResponse => "delegated-response",
            Self::ExportGrant => "export-grant",
            Self::Runtime => "runtime",
            Self::Ledger => "ledger",
            Self::Manifest => "manifest",
        }
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The result of one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Hex of the 16-byte key identifier, `derive_kid(public)`.
    pub kid: String,
    /// Ed25519 signature bytes.
    pub signature: [u8; 64],
}

/// A published verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Hex of the 16-byte key identifier, `derive_kid(public)`.
    pub kid: String,
    /// Ed25519 public key.
    pub public_key: [u8; 32],
}

/// The keys a relying party may pin for one purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeKeys {
    /// The key that signs now.
    pub current: PublicKeyInfo,
    /// The key that signed before the last rotation, if any. Never signs again.
    pub previous: Option<PublicKeyInfo>,
}

/// Reports a signing or key-lookup failure without exposing key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// No key is configured for the purpose.
    #[error("no key is configured for purpose {0}")]
    NoKey(Purpose),
    /// The key material or its source is invalid or unreadable.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// The backing signer failed.
    #[error("signer failed: {0}")]
    Backend(String),
}

/// Signs prepared bytes with the key dedicated to a purpose.
///
/// Both methods are async so a KMS or Vault adapter can call out, like
/// [`AsyncSealer`](crate::AsyncSealer). `sign` returns a `Result` because a backend can fail, and
/// `keys` exists because a JWS or COSE header carries the `kid`, which the caller must know
/// before it can build the bytes to sign.
#[async_trait]
pub trait PurposeSigner: Send + Sync {
    /// Signs `input` for `purpose` on behalf of the tenant scope `scope_key`.
    ///
    /// # Errors
    /// Returns [`SignError::NoKey`] when the purpose has no key, or a backend failure.
    async fn sign(
        &self,
        scope_key: &[u8; 32],
        purpose: Purpose,
        input: &[u8],
    ) -> Result<Signed, SignError>;

    /// Returns the current and previous public keys for `purpose`, for publication and pinning.
    ///
    /// # Errors
    /// Returns [`SignError::NoKey`] when the purpose has no key.
    async fn keys(&self, purpose: Purpose) -> Result<PurposeKeys, SignError>;
}
