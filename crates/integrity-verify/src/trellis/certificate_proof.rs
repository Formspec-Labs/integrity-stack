//! Neutral certificate-proof shape consumed by the core verifier.
//!
//! Trellis Core MUST NOT inspect WOS, Formspec, or any consumer-domain
//! field names. It calls [`ResponseProofResolver::resolve`] against opaque
//! payload bytes and either receives a [`CertificateResponseProof`] (the
//! consumer-domain resolver knew how to read this payload), `Ok(None)`
//! (this payload is not a signing-event the resolver can interpret —
//! continue), or `Err(ResolverError)` (the payload claimed to carry a
//! response proof but the proof is malformed — fail closed at the caller).
//!
//! The matching consumer-side implementation lives in
//! `trellis-verify-wos::WosFormspecResolver`. Phase M wires the API surface;
//! Phase N wires the malformed-digest fail-closed path on the resolver
//! implementation side.

use core::fmt;

/// Neutral response-proof shape returned by a [`ResponseProofResolver`].
/// The 32-byte hash is the resolver-domain-defined digest of the response
/// referenced by the certificate's `response_ref`. Trellis Core only
/// compares it against the certificate's `response_ref`; it does not
/// interpret the bytes further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateResponseProof {
    pub response_hash: [u8; 32],
}

/// Errors a [`ResponseProofResolver`] may surface to Trellis Core.
///
/// Phase M defines the surface; Phase N flips the WOS/Formspec resolver's
/// malformed-digest path from silent-skip to
/// [`ResolverError::MalformedResponseDigest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverError {
    MalformedResponseDigest(String),
}

impl fmt::Display for ResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverError::MalformedResponseDigest(detail) => {
                write!(formatter, "malformed response digest: {detail}")
            }
        }
    }
}

impl std::error::Error for ResolverError {}

/// Consumer-domain resolver that reads opaque signing-event payload bytes
/// and returns a [`CertificateResponseProof`] when the resolver recognizes
/// the payload as a signing event with an embedded response proof.
///
/// Trellis Core is the caller. The resolver is the only code path allowed
/// to inspect WOS, Formspec, or any other consumer-domain field names.
pub trait ResponseProofResolver {
    /// Returns `Ok(Some(_))` when the resolver recognizes the payload and
    /// successfully extracts a response proof; `Ok(None)` when the payload
    /// is not a signing-event payload this resolver knows how to interpret;
    /// `Err(_)` when the payload claimed to carry a response proof but the
    /// proof is malformed — callers fail closed.
    fn resolve(
        &self,
        payload_bytes: &[u8],
    ) -> Result<Option<CertificateResponseProof>, ResolverError>;

    /// Returns the resolver-domain principal reference embedded in the
    /// signing-event payload, when the resolver recognizes the payload.
    /// Used by Trellis Core for ADR 0007 §"Verifier obligations" step 6
    /// chain-summary equivalence. Returns `None` when the payload is not
    /// a signing event the resolver can interpret. Reading the principal
    /// from consumer-domain field names is the resolver's responsibility,
    /// not Trellis Core's.
    fn resolve_principal_ref(&self, _payload_bytes: &[u8]) -> Option<String> {
        None
    }
}

/// No-op resolver used by Trellis Core's default `RecordValidator` impl.
/// Always returns `Ok(None)` — every payload is treated as
/// "not-recognizable", which preserves the prior `continue` behavior on
/// Core-only verification paths (no consumer-domain field reading).
pub struct NoopResponseProofResolver;

impl ResponseProofResolver for NoopResponseProofResolver {
    fn resolve(
        &self,
        _payload_bytes: &[u8],
    ) -> Result<Option<CertificateResponseProof>, ResolverError> {
        Ok(None)
    }
}
