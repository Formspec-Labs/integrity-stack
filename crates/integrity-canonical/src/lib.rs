// Rust guideline compliant 2026-02-21

//! Shared canonical JSON byte primitives.
//!
//! This crate owns the `integrity-canonical-json-v1` substrate rule:
//! RFC 8785 JSON Canonicalization Scheme bytes framed as
//! `domain || NUL || canonical-json`.
//!
//! Formspec response signing is a profile over this substrate. Its wire-visible
//! profile name remains `formspec-response-signing-v1`, while the reusable byte
//! primitive is `integrity-canonical-json-v1`.

use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

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

/// Removes profile-excluded fields from a Formspec Response.
///
/// The Formspec response-signing profile omits `authoredSignatures` so later
/// co-signatures do not invalidate earlier signed-payload commitments.
///
/// # Errors
///
/// Returns an error when `response` is not a JSON object.
pub fn canonicalize_response(response: &Value) -> Result<Value, String> {
    match response {
        Value::Object(map) => {
            let mut stripped = map.clone();
            stripped.remove("authoredSignatures");
            Ok(Value::Object(stripped))
        }
        _ => Err("response must be a JSON object".to_string()),
    }
}

/// Serializes a JSON value with RFC 8785 JCS.
///
/// # Errors
///
/// Returns an error when the value cannot be serialized as canonical JSON.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| format!("JCS canonicalization failed: {error}"))
}

/// Builds `domain || NUL || JCS(value)` bytes.
///
/// The NUL separator prevents ambiguous concatenation between a domain tag and
/// the beginning of the canonical JSON document.
///
/// # Errors
///
/// Returns an error when `value` cannot be serialized as canonical JSON.
pub fn domain_separated_canonical_bytes(
    domain: impl AsRef<str>,
    value: &Value,
) -> Result<Vec<u8>, String> {
    let domain = domain.as_ref();
    let canonical_bytes = canonical_json_bytes(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical_bytes.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(DOMAIN_SEPARATOR_BYTE);
    bytes.extend_from_slice(&canonical_bytes);
    Ok(bytes)
}

/// Builds Formspec response-signing preimage bytes.
///
/// # Errors
///
/// Returns an error when `response` is not an object or cannot be serialized as
/// canonical JSON.
pub fn canonical_response_signed_payload_bytes(response: &Value) -> Result<Vec<u8>, String> {
    let canonical = canonicalize_response(response)?;
    domain_separated_canonical_bytes(DOMAIN_SEPARATION, &canonical)
}

/// Builds Formspec response-handoff preimage bytes.
///
/// Unlike [`canonical_response_signed_payload_bytes`], this preserves
/// `authoredSignatures`. Used to produce the handoff hash bound into
/// `IntakeHandoff.responseHash`.
///
/// # Errors
///
/// Returns an error when `response` is not a JSON object or cannot be
/// serialized as canonical JSON.
pub fn canonical_response_handoff_bytes(response: &Value) -> Result<Vec<u8>, String> {
    if !response.is_object() {
        return Err("response must be a JSON object".to_string());
    }
    domain_separated_canonical_bytes(RESPONSE_HANDOFF_DOMAIN, response)
}

/// Canonicalizes raw JSON bytes via RFC 8785 JCS.
///
/// Lets callers pass wire bytes through to the byte authority instead of
/// reserializing a `Value` they parsed elsewhere.
///
/// # Errors
///
/// Returns an error when `input` is not valid JSON or cannot be canonicalized.
pub fn canonical_json_from_bytes(input: &[u8]) -> Result<Vec<u8>, String> {
    let value: Value = serde_json::from_slice(input)
        .map_err(|error| format!("input is not valid JSON: {error}"))?;
    canonical_json_bytes(&value)
}

/// Builds a signed-payload digest for a Formspec Response.
///
/// # Errors
///
/// Returns an error when canonical payload bytes cannot be produced.
pub fn build_signed_payload(
    response: &Value,
    algorithm: DigestAlgorithm,
) -> Result<SignedPayload, String> {
    let canonical_bytes = canonical_response_signed_payload_bytes(response)?;
    let digest = compute_digest(&canonical_bytes, algorithm);

    Ok(SignedPayload {
        canonical_bytes,
        digest_algorithm: algorithm,
        digest,
    })
}

/// Computes a lowercase hex digest for bytes.
pub fn compute_digest(bytes: &[u8], algorithm: DigestAlgorithm) -> String {
    match algorithm {
        DigestAlgorithm::Sha256 => hex::encode(Sha256::digest(bytes)),
        DigestAlgorithm::Sha384 => hex::encode(Sha384::digest(bytes)),
        DigestAlgorithm::Sha512 => hex::encode(Sha512::digest(bytes)),
    }
}

/// Verifies a Formspec response signed-payload digest.
///
/// # Errors
///
/// Returns an error when `algorithm_str` is unsupported or canonical payload
/// bytes cannot be produced.
pub fn verify_signed_payload_digest(
    response: &Value,
    expected_digest: &str,
    algorithm_str: &str,
) -> Result<bool, String> {
    let algorithm = DigestAlgorithm::from_str(algorithm_str)?;
    let payload = build_signed_payload(response, algorithm)?;
    Ok(payload.digest.eq_ignore_ascii_case(expected_digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vector_response() -> Value {
        json!({
            "$formspecResponse": "1.0",
            "id": "resp-001",
            "definitionUrl": "https://example.org/forms/test",
            "definitionVersion": "1.0.0",
            "status": "completed",
            "data": { "z": 1, "a": 2 },
            "authored": "2026-05-08T12:00:00Z",
            "authoredSignatures": [{ "signatureId": "sig-001" }]
        })
    }

    #[test]
    fn canonicalize_omits_authored_signatures() {
        let canonical = canonicalize_response(&vector_response()).unwrap();
        assert!(canonical.get("authoredSignatures").is_none());
        assert_eq!(canonical["id"], "resp-001");
        assert_eq!(canonical["data"]["a"], 2);
    }

    #[test]
    fn signed_payload_bytes_are_domain_nul_jcs_vector() {
        let payload = build_signed_payload(&vector_response(), DigestAlgorithm::Sha256).unwrap();
        let expected_json = concat!(
            r#"{"$formspecResponse":"1.0","#,
            r#""authored":"2026-05-08T12:00:00Z","#,
            r#""data":{"a":2,"z":1},"#,
            r#""definitionUrl":"https://example.org/forms/test","#,
            r#""definitionVersion":"1.0.0","#,
            r#""id":"resp-001","#,
            r#""status":"completed"}"#
        );
        let mut expected_bytes = DOMAIN_SEPARATION.as_bytes().to_vec();
        expected_bytes.push(DOMAIN_SEPARATOR_BYTE);
        expected_bytes.extend_from_slice(expected_json.as_bytes());

        assert_eq!(payload.canonical_bytes, expected_bytes);
        assert_eq!(
            payload.digest,
            "eace0b826e434d2d35d0a0c0d444c76b3b1036c2623116a4d3cc4ca8abb25045"
        );
    }

    #[test]
    fn old_no_nul_preimage_produces_different_digest() {
        let canonical = canonicalize_response(&vector_response()).unwrap();
        let canonical_json = canonical_json_bytes(&canonical).unwrap();
        let mut old_bytes = DOMAIN_SEPARATION.as_bytes().to_vec();
        old_bytes.extend_from_slice(&canonical_json);

        let old_digest = compute_digest(&old_bytes, DigestAlgorithm::Sha256);
        let payload = build_signed_payload(&vector_response(), DigestAlgorithm::Sha256).unwrap();

        assert_eq!(
            old_digest,
            "3dc38482f410f6f495ff8992655570143643abbdb7f61d02b61808a50e304c7a"
        );
        assert_ne!(old_digest, payload.digest);
    }

    #[test]
    fn build_signed_payload_produces_stable_digest() {
        let payload1 = build_signed_payload(&vector_response(), DigestAlgorithm::Sha256).unwrap();
        let payload2 = build_signed_payload(&vector_response(), DigestAlgorithm::Sha256).unwrap();

        assert_eq!(payload1.digest, payload2.digest, "digest must be stable");
        assert_eq!(payload1.digest.len(), 64, "sha-256 produces 64 hex chars");
    }

    #[test]
    fn digest_changes_when_payload_changes() {
        let response1 = vector_response();
        let mut response2 = response1.clone();
        response2["data"]["a"] = json!(3);

        let p1 = build_signed_payload(&response1, DigestAlgorithm::Sha256).unwrap();
        let p2 = build_signed_payload(&response2, DigestAlgorithm::Sha256).unwrap();

        assert_ne!(
            p1.digest, p2.digest,
            "different data yields different digest"
        );
    }

    #[test]
    fn co_signature_stability() {
        let mut base = vector_response();
        base.as_object_mut().unwrap().remove("authoredSignatures");
        let digest_base = build_signed_payload(&base, DigestAlgorithm::Sha256).unwrap();

        let mut with_one_sig = base.clone();
        with_one_sig["authoredSignatures"] = json!([{ "signatureId": "sig-001" }]);
        let digest_one = build_signed_payload(&with_one_sig, DigestAlgorithm::Sha256).unwrap();

        let mut with_two_sigs = base.clone();
        with_two_sigs["authoredSignatures"] = json!([
            { "signatureId": "sig-001" },
            { "signatureId": "sig-002" }
        ]);
        let digest_two = build_signed_payload(&with_two_sigs, DigestAlgorithm::Sha256).unwrap();

        assert_eq!(digest_base.digest, digest_one.digest);
        assert_eq!(digest_base.digest, digest_two.digest);
    }

    #[test]
    fn verify_signed_payload_digest_accepts_matching_digest() {
        let response = vector_response();
        let payload = build_signed_payload(&response, DigestAlgorithm::Sha256).unwrap();
        assert!(verify_signed_payload_digest(&response, &payload.digest, "sha-256").unwrap());
    }

    #[test]
    fn handoff_bytes_retain_authored_signatures() {
        let response = vector_response();
        let handoff = canonical_response_handoff_bytes(&response).unwrap();
        let handoff_text = std::str::from_utf8(&handoff).unwrap();
        assert!(handoff_text.starts_with(RESPONSE_HANDOFF_DOMAIN));
        assert!(handoff_text.contains("authoredSignatures"));
        assert!(handoff_text.contains("sig-001"));
    }

    #[test]
    fn handoff_and_signed_payload_diverge_when_signatures_present() {
        let response = vector_response();
        let handoff = canonical_response_handoff_bytes(&response).unwrap();
        let signed = canonical_response_signed_payload_bytes(&response).unwrap();
        assert_ne!(handoff, signed);
        let handoff_digest = compute_digest(&handoff, DigestAlgorithm::Sha256);
        let signed_digest = compute_digest(&signed, DigestAlgorithm::Sha256);
        assert_ne!(handoff_digest, signed_digest);
    }

    #[test]
    fn handoff_rejects_non_object() {
        let result = canonical_response_handoff_bytes(&json!("not-an-object"));
        assert!(result.is_err());
    }

    #[test]
    fn canonical_json_from_bytes_is_stable_under_whitespace_and_key_order() {
        let a = br#"{"b":2,"a":1}"#;
        let b = br#"  { "a" : 1 , "b" : 2 }  "#;
        let ca = canonical_json_from_bytes(a).unwrap();
        let cb = canonical_json_from_bytes(b).unwrap();
        assert_eq!(ca, cb);
        assert_eq!(std::str::from_utf8(&ca).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_from_bytes_rejects_invalid_json() {
        assert!(canonical_json_from_bytes(b"{not json").is_err());
    }

    #[test]
    fn key_order_does_not_affect_digest() {
        let ordered = json!({
            "$formspecResponse": "1.0",
            "id": "resp-001",
            "data": { "z": 1, "a": 2 },
            "authored": "2026-05-08T12:00:00Z"
        });
        let reversed = json!({
            "authored": "2026-05-08T12:00:00Z",
            "data": { "a": 2, "z": 1 },
            "id": "resp-001",
            "$formspecResponse": "1.0"
        });
        let d1 = build_signed_payload(&ordered, DigestAlgorithm::Sha256).unwrap();
        let d2 = build_signed_payload(&reversed, DigestAlgorithm::Sha256).unwrap();
        assert_eq!(
            d1.digest, d2.digest,
            "digests must be identical regardless of JSON key insertion order"
        );
    }
}
