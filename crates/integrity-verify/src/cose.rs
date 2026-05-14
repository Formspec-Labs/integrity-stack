// Rust guideline compliant 2026-02-21
//! Universal COSE_Sign1 envelope-shape checks.
//!
//! Wraps [`integrity_cose::decode_cose_sign1`] and surfaces
//! envelope-shape findings (missing kid, missing alg, suite_id absent,
//! payload kind) without requiring profile-specific knowledge of what
//! the payload bytes contain.

use integrity_cose::{
    COSE_LABEL_ALG, COSE_LABEL_KID, COSE_LABEL_SUITE_ID, CoseError, CoseSign1, decode_cose_sign1,
};

/// Envelope-shape finding severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseEnvelopeSeverity {
    /// Envelope is structurally invalid for the universal phase.
    Failure,
    /// Envelope is unusual but not invalid (e.g. missing optional headers).
    Advisory,
}

/// One envelope-shape finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoseEnvelopeFinding {
    pub kind: &'static str,
    pub severity: CoseEnvelopeSeverity,
    pub message: String,
}

impl CoseEnvelopeFinding {
    /// Returns `true` when the finding is an advisory rather than a hard failure.
    #[must_use]
    pub fn is_advisory(&self) -> bool {
        matches!(self.severity, CoseEnvelopeSeverity::Advisory)
    }
}

/// Result of running [`CoseEnvelopeCheck::run`].
pub struct CoseEnvelopeCheck {
    pub envelope: CoseSign1,
    pub findings: Vec<CoseEnvelopeFinding>,
}

impl CoseEnvelopeCheck {
    /// Decodes and structurally checks one COSE_Sign1 envelope.
    ///
    /// # Errors
    /// Returns a [`CoseError`] when the bytes do not decode as RFC 9052
    /// COSE_Sign1.
    pub fn run(bytes: &[u8]) -> Result<Self, CoseError> {
        let envelope = decode_cose_sign1(bytes)?;
        let mut findings = Vec::new();

        if envelope.alg().is_none() {
            findings.push(CoseEnvelopeFinding {
                kind: "alg_missing",
                severity: CoseEnvelopeSeverity::Failure,
                message: format!("protected header is missing COSE label {COSE_LABEL_ALG} (alg)"),
            });
        }
        if envelope.kid().is_none() {
            findings.push(CoseEnvelopeFinding {
                kind: "kid_missing",
                severity: CoseEnvelopeSeverity::Advisory,
                message: format!("protected header is missing COSE label {COSE_LABEL_KID} (kid)"),
            });
        }
        if envelope.suite_id().is_none() {
            findings.push(CoseEnvelopeFinding {
                kind: "suite_id_missing",
                severity: CoseEnvelopeSeverity::Advisory,
                message: format!(
                    "protected header is missing COSE label {COSE_LABEL_SUITE_ID} (suite_id)"
                ),
            });
        }

        Ok(Self { envelope, findings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use integrity_cose::{protected_header_bytes, sign1_bytes};

    #[test]
    fn accepts_well_formed_phase_1_envelope() {
        let protected = protected_header_bytes([0x11; 16]);
        let bytes = sign1_bytes(&protected, b"payload", [0u8; 64]);

        let result = CoseEnvelopeCheck::run(&bytes).expect("decode");
        assert!(result.findings.iter().all(|f| f.is_advisory()));
        assert_eq!(result.envelope.kid(), Some(&[0x11u8; 16][..]));
    }

    #[test]
    fn flags_missing_alg() {
        // Build a protected header with kid but no alg.
        let protected = [
            0xa1, // map(1)
            0x04, // label 4 (kid)
            0x42, 0xaa, 0xbb, // bstr len-2 bytes
        ];
        let bytes = sign1_bytes(&protected, b"payload", [0u8; 64]);

        let result = CoseEnvelopeCheck::run(&bytes).expect("decode");
        let alg_missing = result
            .findings
            .iter()
            .any(|f| f.kind == "alg_missing" && !f.is_advisory());
        assert!(alg_missing, "expected alg_missing failure");
    }
}
