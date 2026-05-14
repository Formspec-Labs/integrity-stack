// Rust guideline compliant 2026-02-21
//! Domain-validator extension surface for Trellis verification.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::trellis::certificate_proof::{NoopResponseProofResolver, ResponseProofResolver};
use crate::trellis::types::{TrellisTimestamp, VerificationReport};

/// Domain validation severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// The domain-specific obligation failed.
    Failure,
    /// The domain-specific obligation produced a non-fatal advisory.
    Advisory,
}

/// Domain validation finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainFinding {
    pub kind: String,
    pub event_hash: Option<[u8; 32]>,
    pub severity: Severity,
    pub message: String,
}

impl DomainFinding {
    /// Creates a domain-validation finding.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        event_hash: Option<[u8; 32]>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            event_hash,
            severity,
            message: message.into(),
        }
    }
}

/// Verified event material exposed to consumer-owned validators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainEvent {
    pub event_type: String,
    pub payload: Option<Vec<u8>>,
    pub canonical_event_hash: [u8; 32],
    pub authored_at: TrellisTimestamp,
}

/// Export-bundle context exposed to consumer-owned validators.
pub struct DomainExport<'a> {
    pub events: &'a [DomainEvent],
    pub members: &'a BTreeMap<String, Vec<u8>>,
    pub manifest_extensions: &'a BTreeMap<String, Vec<u8>>,
}

/// Verification report plus consumer-owned domain findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationWithDomain {
    pub trellis: VerificationReport,
    pub domain_findings: Vec<DomainFinding>,
}

/// Consumer-owned domain verifier.
pub trait RecordValidator {
    /// Returns true when the domain owns this identity-attestation event type.
    fn admits_identity_attestation_event_type(&self, _event_type: &str) -> bool {
        false
    }

    /// Validates a verified event chain.
    fn validate_events(&self, _events: &[DomainEvent]) -> Vec<DomainFinding> {
        Vec::new()
    }

    /// Validates a verified export bundle.
    fn validate_export(&self, _export: DomainExport<'_>) -> Vec<DomainFinding> {
        Vec::new()
    }

    /// Returns the consumer-domain resolver used by Trellis Core to extract
    /// certificate response-proof digests from opaque signing-event payload
    /// bytes. Default returns a no-op resolver — Core never reads
    /// consumer-domain field names directly. WOS / Formspec callers
    /// override this to return their `WosFormspecResolver`.
    fn response_proof_resolver(&self) -> &dyn ResponseProofResolver {
        &NoopResponseProofResolver
    }
}

impl RecordValidator for () {}
