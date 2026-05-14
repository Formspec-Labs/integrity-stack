// Rust guideline compliant 2026-02-21
//! Universal canonical-bytes (JCS) digest verification.
//!
//! Wraps [`integrity_canonical::compute_digest`] so the universal phase
//! can verify a JCS-canonical-bytes digest commitment without depending
//! on the profile's payload semantics.

use integrity_canonical::{DigestAlgorithm, compute_digest};

use crate::report::CanonicalDigestCheck;

/// One canonical-bytes finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFinding {
    pub kind: &'static str,
    pub message: String,
}

/// Result of running [`CanonicalCheck::run`].
pub struct CanonicalCheck {
    pub findings: Vec<CanonicalFinding>,
}

impl CanonicalCheck {
    /// Verifies the declared digest matches the canonical bytes.
    #[must_use]
    pub fn run(check: &CanonicalDigestCheck<'_>) -> Self {
        let mut findings = Vec::new();
        let algorithm = match DigestAlgorithm::from_str(check.algorithm_token) {
            Ok(a) => a,
            Err(e) => {
                findings.push(CanonicalFinding {
                    kind: "digest_algorithm_unsupported",
                    message: e,
                });
                return Self { findings };
            }
        };
        let actual_digest = compute_digest(check.bytes, algorithm);
        if !actual_digest.eq_ignore_ascii_case(check.declared_digest) {
            findings.push(CanonicalFinding {
                kind: "canonical_digest_mismatch",
                message: format!(
                    "declared {} digest does not match canonical-bytes digest",
                    check.algorithm_token
                ),
            });
        }
        Self { findings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use integrity_canonical::compute_digest;

    #[test]
    fn accepts_matching_digest() {
        let bytes = b"hello canonical";
        let digest = compute_digest(bytes, DigestAlgorithm::Sha256);
        let check = CanonicalDigestCheck {
            bytes,
            algorithm_token: "sha-256",
            declared_digest: &digest,
        };
        let result = CanonicalCheck::run(&check);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn flags_mismatched_digest() {
        let check = CanonicalDigestCheck {
            bytes: b"hello canonical",
            algorithm_token: "sha-256",
            declared_digest: "deadbeef",
        };
        let result = CanonicalCheck::run(&check);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == "canonical_digest_mismatch")
        );
    }

    #[test]
    fn flags_unsupported_algorithm() {
        let check = CanonicalDigestCheck {
            bytes: b"hello",
            algorithm_token: "md5",
            declared_digest: "x",
        };
        let result = CanonicalCheck::run(&check);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == "digest_algorithm_unsupported")
        );
    }
}
