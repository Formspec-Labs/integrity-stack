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

/// Relying-party verdict state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictState {
    /// The verifier completed the relevant checks and they passed.
    Pass,
    /// The verifier completed the relevant checks and at least one failed.
    Fail,
    /// Earlier failures prevented a defensible answer.
    Indeterminate,
}

/// Final relying-party result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelyingPartyResult {
    /// All blocking verification tiers passed.
    Valid,
    /// At least one blocking verification tier failed.
    Invalid,
    /// Earlier failures prevented a defensible final result.
    Indeterminate,
}

/// Top-level verifier verdict for non-specialist readers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingPartyVerdict {
    pub cryptographic_integrity: VerdictState,
    pub projection_integrity: VerdictState,
    pub domain_admissibility: VerdictState,
    pub relying_party_result: RelyingPartyResult,
    pub blocking_reasons: Vec<String>,
}

impl RelyingPartyVerdict {
    /// Derives a relying-party verdict from substrate and domain outputs.
    #[must_use]
    pub fn from_parts(substrate: &VerificationReport, findings: &[DomainFinding]) -> Self {
        let cryptographic_integrity =
            if substrate.structure_verified && substrate.integrity_verified {
                VerdictState::Pass
            } else {
                VerdictState::Fail
            };
        let substrate_ok = cryptographic_integrity == VerdictState::Pass;
        let projection_integrity = if !substrate_ok {
            VerdictState::Indeterminate
        } else if findings
            .iter()
            .any(|finding| finding.severity == Severity::Failure && is_projection_finding(finding))
        {
            VerdictState::Fail
        } else {
            VerdictState::Pass
        };
        let domain_admissibility = if !substrate_ok {
            VerdictState::Indeterminate
        } else if findings
            .iter()
            .any(|finding| finding.severity == Severity::Failure && !is_projection_finding(finding))
        {
            VerdictState::Fail
        } else {
            VerdictState::Pass
        };

        let mut blocking_reasons = Vec::new();
        if cryptographic_integrity == VerdictState::Fail {
            blocking_reasons.push("substrate_integrity".to_string());
        }
        if projection_integrity == VerdictState::Fail {
            let reason = if findings
                .iter()
                .any(|finding| finding.kind == "signed_acts_projection_mismatch")
            {
                "projection_mismatch"
            } else {
                "projection_integrity"
            };
            blocking_reasons.push(reason.to_string());
        }
        if domain_admissibility == VerdictState::Fail {
            blocking_reasons.push("domain_admissibility".to_string());
        }

        let relying_party_result = if blocking_reasons.is_empty()
            && cryptographic_integrity == VerdictState::Pass
            && projection_integrity == VerdictState::Pass
            && domain_admissibility == VerdictState::Pass
        {
            RelyingPartyResult::Valid
        } else if blocking_reasons.is_empty() {
            RelyingPartyResult::Indeterminate
        } else {
            RelyingPartyResult::Invalid
        };

        Self {
            cryptographic_integrity,
            projection_integrity,
            domain_admissibility,
            relying_party_result,
            blocking_reasons,
        }
    }
}

/// Domain-validator output kept separate from substrate verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainReport {
    pub findings: Vec<DomainFinding>,
}

impl DomainReport {
    /// Builds a domain report from validator findings.
    #[must_use]
    pub fn new(findings: Vec<DomainFinding>) -> Self {
        Self { findings }
    }

    /// Returns true when the domain report contains a failure.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Failure)
    }
}

/// Two-tier verifier output plus relying-party verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayeredVerificationReport {
    pub verdict: RelyingPartyVerdict,
    pub substrate: VerificationReport,
    pub domain: DomainReport,
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

impl VerificationWithDomain {
    /// Returns the substrate report.
    #[must_use]
    pub fn substrate(&self) -> &VerificationReport {
        &self.trellis
    }

    /// Returns the domain report.
    #[must_use]
    pub fn domain_report(&self) -> DomainReport {
        DomainReport::new(self.domain_findings.clone())
    }

    /// Returns the relying-party verdict.
    #[must_use]
    pub fn verdict(&self) -> RelyingPartyVerdict {
        RelyingPartyVerdict::from_parts(&self.trellis, &self.domain_findings)
    }

    /// Returns the full layered report.
    #[must_use]
    pub fn layered_report(&self) -> LayeredVerificationReport {
        LayeredVerificationReport {
            verdict: self.verdict(),
            substrate: self.trellis.clone(),
            domain: self.domain_report(),
        }
    }
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

fn is_projection_finding(finding: &DomainFinding) -> bool {
    matches!(
        finding.kind.as_str(),
        "missing_signed_acts_catalog"
            | "signed_acts_catalog_digest_mismatch"
            | "signed_acts_catalog_invalid"
            | "signed_acts_catalog_unbound"
            | "signed_acts_projection_mismatch"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_failure_keeps_crypto_pass_but_relying_party_fails() {
        let substrate = VerificationReport {
            structure_verified: true,
            integrity_verified: true,
            readability_verified: true,
            ..VerificationReport::default()
        };
        let findings = vec![DomainFinding::new(
            "signed_acts_projection_mismatch",
            None,
            Severity::Failure,
            "projection mismatch",
        )];

        let verdict = RelyingPartyVerdict::from_parts(&substrate, &findings);

        assert_eq!(verdict.cryptographic_integrity, VerdictState::Pass);
        assert_eq!(verdict.projection_integrity, VerdictState::Fail);
        assert_eq!(verdict.domain_admissibility, VerdictState::Pass);
        assert_eq!(verdict.relying_party_result, RelyingPartyResult::Invalid);
        assert_eq!(verdict.blocking_reasons, ["projection_mismatch"]);
    }
}
