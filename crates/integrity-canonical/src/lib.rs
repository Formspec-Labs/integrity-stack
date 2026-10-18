// Rust guideline compliant 2026-02-21

//! Shared canonical JSON byte primitives.
//!
//! This crate owns the `integrity-canonical-json-v1` substrate rule:
//! RFC 8785 JSON Canonicalization Scheme bytes framed as
//! `domain || NUL || canonical-json`, with one deliberate change to RFC 8785
//! §3.2.2.3: a number is written as its *exact* decimal value, laid out the way
//! ECMAScript `Number::toString` lays out digits. RFC 8785 first rounds every
//! number to an IEEE 754 double, which loses digits beyond about 17 and so
//! cannot carry Formspec decimals (at least 18 significant digits, Core §3.4.1).
//! The bytes equal RFC 8785 exactly when a number's text, read as a decimal,
//! is the shortest decimal that round-trips to its nearest double: how
//! ECMAScript prints every number, and how `serde_json` prints every float.
//! Longer text differs. That covers a decimal beyond a double's precision, and a
//! double's full expansion such as 1152921504606846976 (2^60, which `serde_json`
//! prints as a `u64`), where RFC 8785 writes 1152921504606847000.
//! A nonzero number that binary64 round-to-nearest-even takes to zero
//! (magnitude ≤ 2^−1075) or to infinity (magnitude ≥ 2^1024 − 2^970) is refused,
//! as RFC 8785 refuses non-finite values. The decision reads the digits alone,
//! with exponents read up to 10^15, so every implementation agrees.
//!
//! Formspec Response commitments read JSON text (see [`ResponseJson`]), so
//! nothing passes through `f64`. [`canonical_json_bytes`] serves values built in
//! process, whose numbers are exactly what they hold.
//!
//! Formspec response signing is a profile over this substrate. Its wire-visible
//! profile name remains `formspec-response-signing-v1`, while the reusable byte
//! primitive is `integrity-canonical-json-v1`.

mod json;
mod response;

use sha2::{Digest, Sha256, Sha384, Sha512};

#[doc(inline)]
pub use json::{canonical_json_bytes, canonical_json_from_bytes, domain_separated_canonical_bytes};
#[doc(inline)]
pub use response::{
    ResponseJson, build_signed_payload, canonical_response_handoff_bytes,
    canonical_response_signed_payload_bytes, parse_canonical_response_handoff_bytes,
    verify_signed_payload_digest,
};

/// Identifies the shared canonical JSON substrate.
pub const CANONICALIZATION_PRIMITIVE: &str = "integrity-canonical-json-v1";

/// Identifies the Formspec response-signing profile.
pub const CANONICALIZATION_PROFILE: &str = "formspec-response-signing-v1";

/// Separates Formspec signed-payload bytes from other canonical JSON payloads.
pub const DOMAIN_SEPARATION: &str = "formspec.response.signed-payload.v1";

// Two domain strings exist because handoff and signed-payload are distinct
// commitments over the same Response: handoff hashes the envelope including
// `authoredSignatures` (per Core spec §2.1.6.1, responseHash), while
// signed-payload hashes the envelope with `authoredSignatures` omitted (per
// Core spec §2.1.5 Signed Response Payload). Separate domain tags keep their
// preimage spaces disjoint even when the projection happens to coincide.
/// Separates Formspec response-handoff bytes from signed-payload bytes.
pub const RESPONSE_HANDOFF_DOMAIN: &str = "formspec.response.handoff.v1";

/// Separates the domain tag from canonical JSON bytes.
pub const DOMAIN_SEPARATOR_BYTE: u8 = 0;

/// Supported digest algorithms for canonical payload commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256 digest rendered as lowercase hex.
    Sha256,

    /// SHA-384 digest rendered as lowercase hex.
    Sha384,

    /// SHA-512 digest rendered as lowercase hex.
    Sha512,
}

impl DigestAlgorithm {
    /// Parses a schema-visible digest algorithm name.
    ///
    /// # Errors
    ///
    /// Returns an error when `s` is not a supported digest algorithm.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "sha-256" => Ok(Self::Sha256),
            "sha-384" => Ok(Self::Sha384),
            "sha-512" => Ok(Self::Sha512),
            _ => Err(format!("unknown digest algorithm: {s}")),
        }
    }

    /// Returns the schema-visible digest algorithm name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }
}

/// Canonical payload bytes and digest metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload {
    /// Framed preimage bytes: `domain || NUL || canonical-json`.
    pub canonical_bytes: Vec<u8>,

    /// Digest algorithm used for `digest`.
    pub digest_algorithm: DigestAlgorithm,

    /// Lowercase hex digest of `canonical_bytes`.
    pub digest: String,
}

/// Computes the raw digest bytes for bytes.
///
/// Callers that need a non-hex encoding (for example SD-JWT's base64url
/// digests) take the bytes here instead of depending on a hash crate.
#[must_use]
pub fn digest_bytes(bytes: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
    match algorithm {
        DigestAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        DigestAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
        DigestAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

/// Computes HMAC-SHA-256 (RFC 2104) of `message` under `key`.
///
/// A key of any length is accepted. Callers keep their own message framing and tag encoding.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Checks an HMAC-SHA-256 tag in constant time.
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], tag: &[u8; 32]) -> bool {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts keys of any length");
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

/// Computes a lowercase hex digest for bytes.
pub fn compute_digest(bytes: &[u8], algorithm: DigestAlgorithm) -> String {
    hex::encode(digest_bytes(bytes, algorithm))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2.
    #[test]
    fn hmac_sha256_matches_rfc_4231_and_verifies_in_constant_time_api() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(verify_hmac_sha256(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag
        ));
        assert!(!verify_hmac_sha256(
            b"Jefe",
            b"what do ya want for something?",
            &tag
        ));
        assert!(!verify_hmac_sha256(
            b"jefe",
            b"what do ya want for nothing?",
            &tag
        ));
    }
}
