// Rust guideline compliant 2026-02-21

//! Byte-level helpers shared by issue and verify: base64url, digests, JSON admission.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use integrity_canonical::{DigestAlgorithm, canonical_json_bytes, digest_bytes};
use serde_json::Value;

use crate::error::{DisclosureError, ErrorCode, Result};

/// `_sd_alg` value this crate issues and accepts.
pub const SD_ALG: &str = "sha-256";

/// Salt size in bytes: 128 bits, the RFC 9901 §4.2.1 minimum, from `SecureRandom`.
///
/// Raising it changes every disclosure string and so every stored digest; the verifier in pinned
/// mode requires exactly this size.
pub const SALT_BYTES: usize = 16;

/// Largest accepted presentation, in bytes of compact serialization.
///
/// 4 MiB holds the largest allowed claim count with generous values and bounds every
/// allocation the verifier makes.
pub const MAX_PRESENTATION_BYTES: usize = 4 * 1024 * 1024;

/// Largest number of claims one SD-JWT may commit to, and so the largest padded `_sd` it issues.
pub const MAX_CLAIMS: usize = 4096;

/// Largest number of disclosures a presentation may carry.
pub const MAX_DISCLOSURES: usize = MAX_CLAIMS;

/// Largest `_sd` array the verifier reads: twice `MAX_CLAIMS`, so another issuer's looser padding
/// still verifies while the work stays bounded.
pub const MAX_SD_DIGESTS: usize = 2 * MAX_CLAIMS;

/// Longest claim path in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Longest `iss` in bytes.
pub const MAX_ISS_BYTES: usize = 1024;

/// Longest `kid` or `typ` in bytes.
pub const MAX_NAME_BYTES: usize = 256;

/// Deepest JSON nesting accepted anywhere. Checked on text before parsing, so a hostile document
/// cannot exhaust the stack in either language.
pub const MAX_JSON_DEPTH: usize = 32;

/// Length of a base64url SHA-256 digest.
const DIGEST_CHARS: usize = 43;

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn b64_decode(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| {
        DisclosureError::new(ErrorCode::MalformedBase64, "not strict unpadded base64url")
    })
}

/// Computes the RFC 9901 §4.2.3 digest of a disclosure string.
///
/// The hash covers the US-ASCII bytes of the base64url text itself, and the result is base64url.
#[must_use]
pub fn disclosure_digest(encoded: &str) -> String {
    b64_encode(&digest_bytes(encoded.as_bytes(), DigestAlgorithm::Sha256))
}

/// True when `digest` is a canonical base64url encoding of 32 bytes.
pub(crate) fn is_digest(digest: &str) -> bool {
    digest.len() == DIGEST_CHARS && b64_decode(digest).is_ok_and(|bytes| bytes.len() == 32)
}

pub(crate) fn jcs(value: &Value) -> Result<Vec<u8>> {
    canonical_json_bytes(value)
        .map_err(|_| DisclosureError::new(ErrorCode::MalformedJson, "not canonicalizable JSON"))
}

/// Encodes `base64url(JCS([salt, path, value]))`, the pinned disclosure encoding.
pub(crate) fn encode_disclosure(salt: &str, path: &str, value: &Value) -> Result<String> {
    let array = Value::Array(vec![
        Value::String(salt.to_owned()),
        Value::String(path.to_owned()),
        value.clone(),
    ]);
    Ok(b64_encode(&jcs(&array)?))
}

/// True when the JSON text nests deeper than [`MAX_JSON_DEPTH`].
pub(crate) fn too_deep(text: &str) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in text.as_bytes() {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return true;
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    false
}

/// Parses JSON text after the depth bound.
pub(crate) fn parse_json(text: &str) -> Result<Value> {
    if too_deep(text) {
        return Err(DisclosureError::new(
            ErrorCode::MalformedJson,
            "JSON nests too deeply",
        ));
    }
    serde_json::from_str(text)
        .map_err(|_| DisclosureError::new(ErrorCode::MalformedJson, "not valid JSON"))
}

/// What a claim value contains that this profile cannot carry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Scan {
    Clean,
    TooDeep,
    /// An `_sd` or `...` key, which a standard verifier would treat as a nested disclosure.
    ReservedKey,
}

/// Looks for nesting beyond the bound and for keys with RFC 9901 meaning.
pub(crate) fn scan_value(value: &Value, depth: usize) -> Scan {
    if depth > MAX_JSON_DEPTH {
        return Scan::TooDeep;
    }
    match value {
        Value::Array(items) => {
            for item in items {
                let inner = scan_value(item, depth + 1);
                if inner != Scan::Clean {
                    return inner;
                }
            }
            Scan::Clean
        }
        Value::Object(map) => {
            for (key, item) in map {
                if key == "_sd" || key == "..." {
                    return Scan::ReservedKey;
                }
                let inner = scan_value(item, depth + 1);
                if inner != Scan::Clean {
                    return inner;
                }
            }
            Scan::Clean
        }
        _ => Scan::Clean,
    }
}

/// Claim names the issuer refuses and the verifier rejects as disclosure paths.
///
/// A closed set, so a respondent-controlled path can never act as structure or as a claim a
/// standard JWT library interprets:
/// - RFC 9901 structure: `_sd`, `_sd_alg`, `...`;
/// - RFC 7519 registered names (`exp`, `nbf`, `sub` and the rest), which libraries such as
///   sd-jwt-js read as validity claims or the subject, plus `cnf`, `vct` and `status`;
/// - every `Object.prototype` member, which JavaScript libraries refuse because they test
///   `key in payload`.
pub const REFUSED_CLAIM_NAMES: &[&str] = &[
    "_sd",
    "_sd_alg",
    "...",
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "cnf",
    "vct",
    "status",
    "__proto__",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];

pub(crate) fn is_reserved_name(name: &str) -> bool {
    REFUSED_CLAIM_NAMES.contains(&name)
}

/// Reads the claim path out of an encoded disclosure, so callers never trust a stored copy.
pub(crate) fn disclosure_path(encoded: &str) -> Result<String> {
    let bytes = b64_decode(encoded)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| DisclosureError::new(ErrorCode::MalformedDisclosure, "not UTF-8"))?;
    match parse_json(&text)? {
        Value::Array(items) if items.len() == 3 => match &items[1] {
            Value::String(path) => Ok(path.clone()),
            _ => Err(DisclosureError::new(
                ErrorCode::MalformedDisclosure,
                "claim name must be a string",
            )),
        },
        _ => Err(DisclosureError::new(
            ErrorCode::MalformedDisclosure,
            "disclosure is not [salt, name, value]",
        )),
    }
}
