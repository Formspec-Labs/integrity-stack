// Rust guideline compliant 2026-02-21

//! Byte-building seams for sealing workflows.
//!
//! This module owns the synchronous, deterministic portion of sealing:
//! canonicalize the JSON payload, domain-separate the bytes, compute the
//! event hash, and derive the key identifier. Signature-suite-specific helpers
//! live in sibling crates such as `integrity-cose`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Phase-1 signing suite identifier used by current integrity profiles.
const SUITE_ID_PHASE_1: u64 = 1;

/// Identifies the suite-specific material used to derive a signing `kid`.
///
/// This enum is intentionally locked to Trellis Core §8 signing-key-registry
/// suite codepoints. Phase 1 Ed25519 is the only staffed suite today; future
/// variants must name the Core §8 codepoint they widen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KidInput {
    /// Phase-1 Ed25519 public key bytes.
    Phase1Ed25519([u8; 32]),
}

/// Describes one payload that should become a seal input.
#[derive(Debug, Clone)]
pub struct SealRequest {
    /// Domain tag prepended to the canonical payload bytes.
    pub domain: String,

    /// JSON payload to canonicalize.
    pub payload: serde_json::Value,

    /// Suite-specific material for `kid` derivation.
    pub kid_input: KidInput,
}

/// Contains deterministic bytes ready for signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealInput {
    /// Domain tag used for domain separation.
    pub domain: String,

    /// RFC 8785 canonical JSON payload bytes.
    pub canonical_bytes: Vec<u8>,

    /// Domain-separated payload bytes.
    pub domain_separated_bytes: Vec<u8>,

    /// SHA-256 hash of the domain-separated payload.
    pub canonical_event_hash: String,

    /// Hex-encoded 16-byte key identifier.
    pub kid: String,
}

/// Represents a signed seal envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// Domain tag used for the signed payload.
    pub domain: String,

    /// Hex-encoded 16-byte key identifier.
    pub kid: String,

    /// Base64-encoded COSE_Sign1 bytes.
    pub cose_sign1_b64: String,

    /// SHA-256 hash of the signed domain-separated payload.
    pub canonical_event_hash: String,
}

/// Reports seal-input construction and signing failures.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SealError {
    /// Canonical JSON serialization failed.
    #[error("canonicalize: {0}")]
    Canonicalize(String),

    /// Signature-suite-specific signing failed.
    #[error("sign: {0}")]
    Sign(String),
}

/// Builds deterministic seal inputs from application requests.
pub trait SealInputBuilder: Send + Sync {
    /// Builds a seal input from `req`.
    ///
    /// # Errors
    /// Returns an error when canonical JSON bytes cannot be produced.
    fn build_seal_input(&self, req: &SealRequest) -> Result<SealInput, SealError>;
}

/// Signs deterministic seal inputs asynchronously.
#[async_trait]
pub trait AsyncSealer: Send + Sync {
    /// Signs `input` and returns a sealed envelope.
    ///
    /// # Errors
    /// Returns an error when the concrete signing implementation fails.
    async fn sign(&self, input: &SealInput) -> Result<SealedEnvelope, SealError>;
}

/// Builds the default deterministic seal input.
///
/// # Errors
/// Returns an error when canonical JSON bytes cannot be produced.
pub fn default_seal_input(req: &SealRequest) -> Result<SealInput, SealError> {
    let canonical_bytes = integrity_canonical::canonical_json_bytes(&req.payload)
        .map_err(|error| SealError::Canonicalize(error.to_string()))?;
    let mut domain_separated_bytes =
        Vec::with_capacity(req.domain.len() + 1 + canonical_bytes.len());
    domain_separated_bytes.extend_from_slice(req.domain.as_bytes());
    domain_separated_bytes.push(integrity_canonical::DOMAIN_SEPARATOR_BYTE);
    domain_separated_bytes.extend_from_slice(&canonical_bytes);

    let digest = integrity_cbor::sha256_bytes(&domain_separated_bytes);
    let canonical_event_hash = format!("sha256:{}", hex::encode(digest));
    let kid = hex::encode(derive_kid(req.kid_input));

    Ok(SealInput {
        domain: req.domain.clone(),
        canonical_bytes,
        domain_separated_bytes,
        canonical_event_hash,
        kid,
    })
}

fn derive_kid(kid_input: KidInput) -> [u8; 16] {
    match kid_input {
        KidInput::Phase1Ed25519(public_key) => derive_phase1_kid(public_key),
    }
}

/// Derives the Phase-1 Ed25519 `kid`.
///
/// This intentionally mirrors `integrity_cose::derive_kid` without depending
/// on `integrity-cose`: `integrity-seam` is the substrate byte builder, while
/// `integrity-cose` is the widening point that owns COSE suite helpers.
fn derive_phase1_kid(public_key: [u8; 32]) -> [u8; 16] {
    let mut preimage = integrity_cbor::encode_uint(SUITE_ID_PHASE_1);
    preimage.extend_from_slice(&public_key);
    let digest = integrity_cbor::sha256_bytes(&preimage);
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&digest[..16]);
    kid
}
