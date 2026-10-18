// Rust guideline compliant 2026-02-21
//! Formspec Response profiles over the canonical JSON writer.
//!
//! Every commitment to a Response reads its JSON text, never a parsed
//! `serde_json::Value`: parsing rounds numbers to `f64`, and Formspec decimals
//! need at least 18 significant digits (Core §3.4.1). [`ResponseJson`] carries
//! the text through code that also needs to read fields.

use std::fmt;

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::json::{canonical_json_from_bytes, members, parse_raw, write_members};
use crate::{
    DOMAIN_SEPARATION, DOMAIN_SEPARATOR_BYTE, DigestAlgorithm, RESPONSE_HANDOFF_DOMAIN,
    SignedPayload, compute_digest,
};

/// The member the signing profile omits, so co-signatures keep earlier digests valid.
const AUTHORED_SIGNATURES: &str = "authoredSignatures";

/// A Formspec Response held as the JSON text it arrived or was stored as.
///
/// The commitment methods read the text, so every digit of every number
/// counts. [`ResponseJson::value`] is a parsed view for reading fields; its
/// numbers are `f64` and it must never be re-encoded for a commitment. Serde
/// writes and reads the text verbatim (through `serde_json`'s `RawValue`), so a
/// record that stores or sends a `ResponseJson` keeps its digits.
#[derive(Clone)]
pub struct ResponseJson {
    text: String,
    value: Value,
}

impl ResponseJson {
    /// Admits Response JSON text.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not one JSON object with unique
    /// member names and numbers inside the binary64 range.
    pub fn parse(text: impl Into<String>) -> Result<Self, String> {
        let text = text.into();
        canonical_response_handoff_bytes(text.as_bytes())?;
        let value = serde_json::from_str(&text)
            .map_err(|error| format!("response is not valid JSON: {error}"))?;
        Ok(Self { text, value })
    }

    /// Writes an in-process Response value as text.
    ///
    /// Exact only for the numbers `value` holds: a `Value` parsed from text has
    /// already rounded them. Use it only where no text exists, such as a Response
    /// built in process or one a route already parsed (fs-ecbq).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ResponseJson::parse`].
    pub fn from_value(value: &Value) -> Result<Self, String> {
        Self::parse(value.to_string())
    }

    /// Returns the Response JSON text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the parsed view for reading fields; never commit to it.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Builds the response-handoff preimage over the complete Response.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`canonical_response_handoff_bytes`].
    pub fn handoff_bytes(&self) -> Result<Vec<u8>, String> {
        canonical_response_handoff_bytes(self.text.as_bytes())
    }

    /// Returns `sha256:` and the hex SHA-256 of the handoff preimage.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`canonical_response_handoff_bytes`].
    pub fn handoff_hash(&self) -> Result<String, String> {
        Ok(format!(
            "sha256:{}",
            compute_digest(&self.handoff_bytes()?, DigestAlgorithm::Sha256)
        ))
    }

    /// Builds the signed-payload preimage and digest.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`canonical_response_signed_payload_bytes`].
    pub fn signed_payload(&self, algorithm: DigestAlgorithm) -> Result<SignedPayload, String> {
        build_signed_payload(self.text.as_bytes(), algorithm)
    }

    /// Returns this Response with the top-level member `name` set to `member`.
    ///
    /// Every other member keeps its text exactly as written; an existing
    /// `name` member is replaced.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ResponseJson::parse`] for the result.
    pub fn with_member(&self, name: &str, member: &Value) -> Result<Self, String> {
        let mut text = String::with_capacity(self.text.len() + 256);
        text.push('{');
        for (key, raw) in members(&self.text)? {
            if key != name {
                text.push_str(&Value::String(key).to_string());
                text.push(':');
                text.push_str(raw.get());
                text.push(',');
            }
        }
        text.push_str(&Value::String(name.to_owned()).to_string());
        text.push(':');
        text.push_str(&member.to_string());
        text.push('}');
        Self::parse(text)
    }
}

impl PartialEq for ResponseJson {
    /// Two Responses are equal when their canonical bytes are.
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
            || canonical_json_from_bytes(self.text.as_bytes()).ok()
                == canonical_json_from_bytes(other.text.as_bytes()).ok()
    }
}

impl Eq for ResponseJson {}

impl fmt::Debug for ResponseJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

impl Serialize for ResponseJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_json::from_str::<&RawValue>(&self.text)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResponseJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        Self::parse(String::from(Box::<str>::from(raw))).map_err(D::Error::custom)
    }
}

/// Builds the Formspec response-handoff preimage from Response JSON text.
///
/// The bytes are `formspec.response.handoff.v1 || NUL || canonical-json`, over
/// the complete Response including `authoredSignatures`; their SHA-256 is
/// `IntakeHandoff.responseHash`. Numbers are read as text.
///
/// # Errors
///
/// Returns an error when `response_json` is not valid JSON, its root is not an
/// object, an object repeats a member name, or a number lies outside the
/// binary64 range.
pub fn canonical_response_handoff_bytes(response_json: &[u8]) -> Result<Vec<u8>, String> {
    framed_response(RESPONSE_HANDOFF_DOMAIN, response_json, None)
}

/// Builds the Formspec response-signing preimage from Response JSON text.
///
/// The bytes are `formspec.response.signed-payload.v1 || NUL || canonical-json`
/// of the Response without its top-level `authoredSignatures` member.
///
/// # Errors
///
/// Returns the errors of [`canonical_response_handoff_bytes`], including for
/// malformed content inside the omitted member.
pub fn canonical_response_signed_payload_bytes(response_json: &[u8]) -> Result<Vec<u8>, String> {
    framed_response(DOMAIN_SEPARATION, response_json, Some(AUTHORED_SIGNATURES))
}

/// Builds a signed-payload digest from Formspec Response JSON text.
///
/// # Errors
///
/// Returns the errors of [`canonical_response_signed_payload_bytes`].
pub fn build_signed_payload(
    response_json: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<SignedPayload, String> {
    let canonical_bytes = canonical_response_signed_payload_bytes(response_json)?;
    let digest = compute_digest(&canonical_bytes, algorithm);
    Ok(SignedPayload {
        canonical_bytes,
        digest_algorithm: algorithm,
        digest,
    })
}

/// Verifies a Formspec signed-payload digest against Response JSON text.
///
/// # Errors
///
/// Returns an error when `algorithm_str` is unsupported or the preimage
/// cannot be built.
pub fn verify_signed_payload_digest(
    response_json: &[u8],
    expected_digest: &str,
    algorithm_str: &str,
) -> Result<bool, String> {
    let algorithm = DigestAlgorithm::from_str(algorithm_str)?;
    let payload = build_signed_payload(response_json, algorithm)?;
    Ok(payload.digest.eq_ignore_ascii_case(expected_digest))
}

/// Decodes bytes produced by [`canonical_response_handoff_bytes`].
///
/// Accepts only the exact domain tag, separator byte and canonical JSON, so a
/// consumer of protected Response plaintext cannot accept another encoding.
/// The returned Response keeps the canonical text.
///
/// # Errors
///
/// Returns an error when the domain tag, JSON or canonical form differs.
pub fn parse_canonical_response_handoff_bytes(bytes: &[u8]) -> Result<ResponseJson, String> {
    let json = bytes
        .strip_prefix(RESPONSE_HANDOFF_DOMAIN.as_bytes())
        .and_then(|rest| rest.strip_prefix(&[DOMAIN_SEPARATOR_BYTE]))
        .ok_or("response handoff domain tag differs")?;
    let text = std::str::from_utf8(json).map_err(|_| "response handoff JSON is invalid")?;
    let response =
        ResponseJson::parse(text).map_err(|_| "response handoff JSON is invalid".to_string())?;
    if response.handoff_bytes()? != bytes {
        return Err("response handoff bytes are not canonical".to_string());
    }
    Ok(response)
}

fn framed_response(
    domain: &str,
    response_json: &[u8],
    omitted: Option<&str>,
) -> Result<Vec<u8>, String> {
    let raw = parse_raw(response_json)?;
    if !raw.get().starts_with('{') {
        return Err("response must be a JSON object".to_string());
    }
    let mut bytes = Vec::with_capacity(domain.len() + 1 + response_json.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(DOMAIN_SEPARATOR_BYTE);
    write_members(&mut bytes, members(raw.get())?, omitted)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_separated_canonical_bytes;
    use crate::json::canonical_json_bytes;

    const VECTOR_RESPONSE: &str = r#"{"$formspecResponse":"1.0","id":"resp-001",
        "definitionUrl":"https://example.org/forms/test","definitionVersion":"1.0.0",
        "status":"completed","data":{"z":1,"a":2},"authored":"2026-05-08T12:00:00Z",
        "authoredSignatures":[{"signatureId":"sig-001"}]}"#;

    fn response() -> ResponseJson {
        ResponseJson::parse(VECTOR_RESPONSE).unwrap()
    }

    #[test]
    fn signed_payload_bytes_are_domain_nul_canonical_json_vector() {
        let payload = response().signed_payload(DigestAlgorithm::Sha256).unwrap();
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
        assert!(
            verify_signed_payload_digest(VECTOR_RESPONSE.as_bytes(), &payload.digest, "sha-256")
                .unwrap()
        );
    }

    #[test]
    fn signed_payload_ignores_signatures_and_member_order_but_not_data() {
        let base = response().signed_payload(DigestAlgorithm::Sha256).unwrap();
        for signatures in [
            serde_json::json!([]),
            serde_json::json!([{"signatureId": "a"}, {"signatureId": "b"}]),
        ] {
            let other = response()
                .with_member("authoredSignatures", &signatures)
                .unwrap();
            assert_eq!(other.signed_payload(DigestAlgorithm::Sha256).unwrap(), base);
        }
        let reordered = r#"{"authored":"2026-05-08T12:00:00Z","data":{"a":2,"z":1},"id":"resp-001",
            "definitionVersion":"1.0.0","definitionUrl":"https://example.org/forms/test",
            "status":"completed","$formspecResponse":"1.0"}"#;
        assert_eq!(
            build_signed_payload(reordered.as_bytes(), DigestAlgorithm::Sha256).unwrap(),
            base
        );
        let changed = response()
            .with_member("data", &serde_json::json!({"z": 1, "a": 3}))
            .unwrap();
        assert_ne!(
            changed
                .signed_payload(DigestAlgorithm::Sha256)
                .unwrap()
                .digest,
            base.digest
        );
    }

    #[test]
    fn handoff_keeps_signatures_and_diverges_from_the_signed_payload() {
        let handoff = response().handoff_bytes().unwrap();
        let text = std::str::from_utf8(&handoff).unwrap();
        assert!(text.starts_with(RESPONSE_HANDOFF_DOMAIN) && text.contains("sig-001"));
        let signed = canonical_response_signed_payload_bytes(VECTOR_RESPONSE.as_bytes()).unwrap();
        assert_ne!(handoff, signed);
        assert!(canonical_response_handoff_bytes(br#""not-an-object""#).is_err());
        assert!(ResponseJson::parse("[]").is_err());
    }

    #[test]
    fn a_nineteen_digit_decimal_keeps_every_digit_through_parse_sign_and_storage() {
        let response = ResponseJson::parse(
            r#"{"id":"r-1","data":{"amount":1234567890.123456789},"authoredSignatures":[]}"#,
        )
        .unwrap();
        let handoff = response.handoff_bytes().unwrap();
        let reread = parse_canonical_response_handoff_bytes(&handoff).unwrap();
        assert_eq!(reread, response);
        assert_eq!(reread.value()["id"], "r-1");
        assert!(reread.as_str().contains("1234567890.123456789"));
        let signed = response.signed_payload(DigestAlgorithm::Sha256).unwrap();
        let signed_json =
            std::str::from_utf8(&signed.canonical_bytes[DOMAIN_SEPARATION.len() + 1..]).unwrap();
        assert_eq!(
            signed_json,
            r#"{"data":{"amount":1234567890.123456789},"id":"r-1"}"#
        );
        // Stored inside a larger record, the text survives verbatim.
        let record = serde_json::to_string(&vec![response.clone()]).unwrap();
        assert!(record.contains("1234567890.123456789"));
        let restored: Vec<ResponseJson> = serde_json::from_str(&record).unwrap();
        assert_eq!(restored[0].handoff_bytes().unwrap(), handoff);
        let signed_response = response
            .with_member(
                "authoredSignatures",
                &serde_json::json!([{"signatureId": "s"}]),
            )
            .unwrap();
        assert!(signed_response.as_str().contains("1234567890.123456789"));
    }

    #[test]
    fn text_functions_refuse_repeated_members_and_bad_omitted_content() {
        assert!(ResponseJson::parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(
            canonical_response_signed_payload_bytes(
                br#"{"authoredSignatures":[{"value":"\ud800"}]}"#
            )
            .is_err()
        );
        assert!(
            canonical_response_signed_payload_bytes(br#"{"authoredSignatures":[1e400]}"#).is_err()
        );
    }

    #[test]
    fn handoff_bytes_round_trip_and_other_encodings_refuse() {
        let text = r#"{"id":"r-1","data":{"b":2,"a":1}}"#;
        let bytes = canonical_response_handoff_bytes(text.as_bytes()).unwrap();
        assert_eq!(
            parse_canonical_response_handoff_bytes(&bytes).unwrap(),
            ResponseJson::parse(text).unwrap()
        );
        let value: Value = serde_json::from_str(text).unwrap();
        // Bare canonical JSON, a foreign domain and non-canonical spacing all refuse.
        assert!(
            parse_canonical_response_handoff_bytes(&canonical_json_bytes(&value).unwrap()).is_err()
        );
        let foreign = domain_separated_canonical_bytes("formspec.other.v1", &value).unwrap();
        assert!(parse_canonical_response_handoff_bytes(&foreign).is_err());
        let mut spaced = RESPONSE_HANDOFF_DOMAIN.as_bytes().to_vec();
        spaced.push(DOMAIN_SEPARATOR_BYTE);
        spaced.extend_from_slice(br#"{ "id": "r-1", "data": {"a": 1, "b": 2} }"#);
        assert!(parse_canonical_response_handoff_bytes(&spaced).is_err());
    }
}
