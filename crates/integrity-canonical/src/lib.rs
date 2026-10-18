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
//! The `*_from_json` functions read numbers as text, so nothing passes through
//! `f64`. The `&Value` functions are exact for the numbers a `serde_json::Value`
//! holds, which were already rounded to `f64` if the Value was parsed from text.
//!
//! Formspec response signing is a profile over this substrate. Its wire-visible
//! profile name remains `formspec-response-signing-v1`, while the reusable byte
//! primitive is `integrity-canonical-json-v1`.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;
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

/// Serializes a JSON value under `integrity-canonical-json-v1`.
///
/// # Errors
///
/// Returns an error when a number lies outside the binary64 range.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_value(&mut out, value)?;
    Ok(out)
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

/// Builds Formspec response-handoff preimage bytes from Response JSON text.
///
/// Reads numbers as text, so a decimal keeps every digit the sender wrote.
/// Prefer this over [`canonical_response_handoff_bytes`] whenever the
/// Response arrives or is stored as JSON text.
///
/// # Errors
///
/// Returns an error when `response_json` is not valid JSON, its root is not an
/// object, an object repeats a member name, or a number lies outside the
/// binary64 range.
pub fn canonical_response_handoff_bytes_from_json(response_json: &[u8]) -> Result<Vec<u8>, String> {
    framed_response_from_json(RESPONSE_HANDOFF_DOMAIN, response_json, None)
}

/// Builds Formspec response-signing preimage bytes from Response JSON text.
///
/// The text counterpart of [`canonical_response_signed_payload_bytes`]: it
/// omits top-level `authoredSignatures` and keeps every digit of every number.
///
/// # Errors
///
/// Returns the errors of [`canonical_response_handoff_bytes_from_json`],
/// including for malformed content inside the omitted member.
pub fn canonical_response_signed_payload_bytes_from_json(
    response_json: &[u8],
) -> Result<Vec<u8>, String> {
    framed_response_from_json(DOMAIN_SEPARATION, response_json, Some("authoredSignatures"))
}

/// Builds a signed-payload digest from Formspec Response JSON text.
///
/// # Errors
///
/// Returns the errors of [`canonical_response_signed_payload_bytes_from_json`].
pub fn build_signed_payload_from_json(
    response_json: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<SignedPayload, String> {
    let canonical_bytes = canonical_response_signed_payload_bytes_from_json(response_json)?;
    let digest = compute_digest(&canonical_bytes, algorithm);
    Ok(SignedPayload {
        canonical_bytes,
        digest_algorithm: algorithm,
        digest,
    })
}

/// Decodes bytes produced by [`canonical_response_handoff_bytes`].
///
/// Accepts only the exact domain tag, separator byte and canonical JSON, so a
/// consumer of protected Response plaintext cannot accept another encoding.
/// The canonical check reads numbers as text. The returned `Value` holds
/// numbers as `f64`, so commit to `bytes`, never to a re-encoding of the Value.
///
/// # Errors
///
/// Returns an error when the domain tag, JSON or canonical form differs.
pub fn parse_canonical_response_handoff_bytes(bytes: &[u8]) -> Result<Value, String> {
    let json = bytes
        .strip_prefix(RESPONSE_HANDOFF_DOMAIN.as_bytes())
        .and_then(|rest| rest.strip_prefix(&[DOMAIN_SEPARATOR_BYTE]))
        .ok_or("response handoff domain tag differs")?;
    let canonical = canonical_response_handoff_bytes_from_json(json)
        .map_err(|_| "response handoff JSON is invalid".to_string())?;
    if canonical != bytes {
        return Err("response handoff bytes are not canonical".to_string());
    }
    serde_json::from_slice(json).map_err(|_| "response handoff JSON is invalid".to_string())
}

/// Canonicalizes raw JSON bytes under `integrity-canonical-json-v1`.
///
/// Lets callers pass wire bytes through to the byte authority instead of
/// reserializing a `Value` they parsed elsewhere. Numbers are read as text.
///
/// # Errors
///
/// Returns an error when `input` is not valid JSON, an object repeats a member
/// name, or a number lies outside the binary64 range.
pub fn canonical_json_from_bytes(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_json_text(&mut out, parse_raw(input)?)?;
    Ok(out)
}

fn framed_response_from_json(
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

fn parse_raw(input: &[u8]) -> Result<&RawValue, String> {
    serde_json::from_slice(input).map_err(|error| format!("input is not valid JSON: {error}"))
}

fn members(object: &str) -> Result<Vec<(String, &RawValue)>, String> {
    serde_json::from_str::<RawMembers<'_>>(object)
        .map(|members| members.0)
        .map_err(|error| format!("input is not valid JSON: {error}"))
}

/// One JSON object's members in document order, each value kept as raw text.
struct RawMembers<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for RawMembers<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MembersVisitor;
        impl<'de> Visitor<'de> for MembersVisitor {
            type Value = RawMembers<'de>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut members = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    members.push((key, map.next_value::<&'de RawValue>()?));
                }
                Ok(RawMembers(members))
            }
        }
        deserializer.deserialize_map(MembersVisitor)
    }
}

// Each container re-reads its own slice, so work grows with size times depth;
// serde_json's recursion limit (128) bounds the depth.
fn write_json_text(out: &mut Vec<u8>, raw: &RawValue) -> Result<(), String> {
    let text = raw.get();
    let invalid = |error: serde_json::Error| format!("input is not valid JSON: {error}");
    match text.as_bytes().first() {
        Some(b'{') => write_members(out, members(text)?, None),
        Some(b'[') => {
            let items: Vec<&RawValue> = serde_json::from_str(text).map_err(invalid)?;
            out.push(b'[');
            for (index, item) in items.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_text(out, item)?;
            }
            out.push(b']');
            Ok(())
        }
        Some(b'"') => write_string(out, &serde_json::from_str::<String>(text).map_err(invalid)?),
        // serde_json admitted the token, so these are exactly `true`, `false` or `null`.
        Some(b't' | b'f' | b'n') => {
            out.extend_from_slice(text.as_bytes());
            Ok(())
        }
        _ => write_number(out, text),
    }
}

fn write_members(
    out: &mut Vec<u8>,
    mut members: Vec<(String, &RawValue)>,
    omitted: Option<&str>,
) -> Result<(), String> {
    members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
    // RFC 8785 §3.1 requires I-JSON, whose member names are unique.
    if members.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("JSON object repeats a member name".to_string());
    }
    out.push(b'{');
    let mut first = true;
    for (key, value) in members {
        if Some(key.as_str()) == omitted {
            // An omitted member must still be valid canonical input.
            write_json_text(&mut Vec::new(), value)?;
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        write_string(out, &key)?;
        out.push(b':');
        write_json_text(out, value)?;
    }
    out.push(b'}');
    Ok(())
}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(out, &number.to_string())?,
        Value::String(text) => write_string(out, text)?,
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut members: Vec<_> = map.iter().collect();
            members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            out.push(b'{');
            for (index, (key, item)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(out, key)?;
                out.push(b':');
                write_value(out, item)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

// serde_json escapes exactly as RFC 8785 §3.2.2.2 does: `"`, `\\` and the
// control characters, with lowercase `\u00xx` for those lacking a short form.
fn write_string(out: &mut Vec<u8>, text: &str) -> Result<(), String> {
    serde_json::to_writer(&mut *out, text).map_err(|error| format!("string write failed: {error}"))
}

/// Largest exponent magnitude read from number text.
///
/// Any larger exponent already puts a nonzero value far outside the binary64
/// range, unless the text has about 10^15 digits. The TypeScript and Python
/// implementations stop reading at the same bound, so all three agree.
const MAX_EXPONENT: i64 = 1_000_000_000_000_000;

/// Digits of 2^1024 − 2^970 (value = 0.DIGITS × 10^309), the least magnitude
/// binary64 round-to-nearest-even takes to infinity.
const OVERFLOW_DIGITS: &str = concat!(
    "17976931348623158079372897140530341507993413271003782693617377898044496829276475",
    "09466490179775872070963302864166928879109465555478519404026306574886715058206819",
    "08902000708383676273854845817711531764475730270069855571366959622842914819860834",
    "936475292719074168444365510704342711559699508093042880177904174497792",
);
const OVERFLOW_N: i64 = 309;

/// Digits of 2^−1075 = 5^1075 / 10^1075 (value = 0.DIGITS × 10^−323), the
/// greatest magnitude binary64 round-to-nearest-even takes to zero.
const UNDERFLOW_DIGITS: &str = concat!(
    "24703282292062327208828439643411068618252990130716238221279284125033775363510437",
    "59326499181808179961898982823477228588654633283551779698981993873980053909390631",
    "50356595155702263922908583924491051844359318028499365361525003193704576782492193",
    "65623669863658480757001585769269903706311928279558551332927834338409351978015531",
    "24659726357957462276646527282722005637400648549997709659947045402082816622623785",
    "73934507363390079677619305775067401763246736009689513405355374585166611342237666",
    "78604162159680461914467291840300530057530849048765391711386591646239524912623653",
    "88187963623937328042389101867234849766823508986338858792562830275599565752445550",
    "72551893136908362547791869486679949683240497058210285131854513962138377228261454",
    "37693412532098591327667236328125",
);
const UNDERFLOW_N: i64 = -323;

/// Compares 0.`digits` with 0.`bound`; neither has trailing zeros.
fn compare_fraction(digits: &[u8], bound: &str) -> std::cmp::Ordering {
    let bound = bound.as_bytes();
    let common = digits.len().min(bound.len());
    digits[..common]
        .cmp(&bound[..common])
        .then(digits.len().cmp(&bound.len()))
}

/// Writes a JSON number as its exact decimal value in `Number::toString` layout.
///
/// ECMA-262 §6.1.6.1.20 lays out the digits `s` (`k` of them, no trailing
/// zeros) of a value `s × 10^(n−k)`. RFC 8785 takes `s` from the nearest double;
/// this takes it from the decimal text, so no digit is lost. A nonzero value
/// that binary64 rounding takes to zero or infinity is refused, decided from the
/// digits alone, as RFC 8785 refuses non-finite values. One scan, linear in the text.
fn write_number(out: &mut Vec<u8>, text: &str) -> Result<(), String> {
    let invalid = || format!("`{text}` is not a JSON number");
    let bytes = text.as_bytes();
    let digit = |at: usize| bytes.get(at).is_some_and(u8::is_ascii_digit);
    let negative = bytes.first() == Some(&b'-');
    let mut at = usize::from(negative);
    let integer_start = at;
    match bytes.get(at) {
        Some(b'0') => at += 1,
        Some(b'1'..=b'9') => {
            while digit(at) {
                at += 1;
            }
        }
        _ => return Err(invalid()),
    }
    let integer_end = at;
    let (mut fraction_start, mut fraction_end) = (at, at);
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        fraction_start = at;
        while digit(at) {
            at += 1;
        }
        fraction_end = at;
        if fraction_end == fraction_start {
            return Err(invalid());
        }
    }
    let mut exponent: i64 = 0;
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        at += 1;
        let sign = match bytes.get(at) {
            Some(b'-') => {
                at += 1;
                -1
            }
            Some(b'+') => {
                at += 1;
                1
            }
            _ => 1,
        };
        let start = at;
        while digit(at) {
            if exponent < MAX_EXPONENT {
                exponent = exponent * 10 + i64::from(bytes[at] - b'0');
            }
            at += 1;
        }
        if at == start {
            return Err(invalid());
        }
        exponent *= sign;
    }
    if at != bytes.len() {
        return Err(invalid());
    }
    let nonzero = |range: std::ops::Range<usize>| bytes[range].iter().position(|&b| b != b'0');
    let last_nonzero =
        |range: std::ops::Range<usize>| bytes[range].iter().rposition(|&b| b != b'0');
    let first_in_integer = nonzero(integer_start..integer_end).map(|i| integer_start + i);
    let Some(first) = first_in_integer
        .or_else(|| nonzero(fraction_start..fraction_end).map(|i| fraction_start + i))
    else {
        out.push(b'0');
        return Ok(());
    };
    let last_in_fraction = last_nonzero(fraction_start..fraction_end).map(|i| fraction_start + i);
    let last = last_in_fraction
        .or_else(|| last_nonzero(integer_start..integer_end).map(|i| integer_start + i))
        .unwrap_or(first);
    let digits: std::borrow::Cow<'_, [u8]> =
        if first_in_integer.is_some() && last_in_fraction.is_some() {
            [&bytes[first..integer_end], &bytes[fraction_start..=last]]
                .concat()
                .into()
        } else {
            (&bytes[first..=last]).into()
        };
    let to_i64 = |count: usize| i64::try_from(count).map_err(|_| invalid());
    // value = 0.digits × 10^n; |n| stays below 2^62 because the exponent is capped.
    let n = exponent
        + if first_in_integer.is_some() {
            to_i64(integer_end - first)?
        } else {
            -to_i64(first - fraction_start)?
        };
    if n > OVERFLOW_N
        || (n == OVERFLOW_N && compare_fraction(&digits, OVERFLOW_DIGITS).is_ge())
        || n < UNDERFLOW_N
        || (n == UNDERFLOW_N && compare_fraction(&digits, UNDERFLOW_DIGITS).is_le())
    {
        return Err(format!("number `{text}` is outside the binary64 range"));
    }
    let k = to_i64(digits.len())?;
    if negative {
        out.push(b'-');
    }
    if k <= n && n <= 21 {
        out.extend_from_slice(&digits);
        out.resize(
            out.len() + usize::try_from(n - k).map_err(|_| invalid())?,
            b'0',
        );
    } else if 0 < n && n <= 21 {
        let (whole, rest) = digits.split_at(usize::try_from(n).map_err(|_| invalid())?);
        out.extend_from_slice(whole);
        out.push(b'.');
        out.extend_from_slice(rest);
    } else if -6 < n && n <= 0 {
        out.extend_from_slice(b"0.");
        out.resize(
            out.len() + usize::try_from(-n).map_err(|_| invalid())?,
            b'0',
        );
        out.extend_from_slice(&digits);
    } else {
        out.push(digits[0]);
        if k > 1 {
            out.push(b'.');
            out.extend_from_slice(&digits[1..]);
        }
        out.push(b'e');
        out.push(if n > 0 { b'+' } else { b'-' });
        out.extend_from_slice((n - 1).unsigned_abs().to_string().as_bytes());
    }
    Ok(())
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

#[cfg(test)]
mod exact_number_tests {
    use super::*;

    fn canonical_text(json: &str) -> Result<String, String> {
        canonical_json_from_bytes(json.as_bytes()).map(|bytes| String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn numbers_take_number_to_string_layout_over_their_exact_digits() {
        for (input, expected) in [
            ("0", "0"),
            ("-0", "0"),
            ("-0.000e5", "0"),
            ("4.50", "4.5"),
            ("123e-2", "1.23"),
            ("2e-3", "0.002"),
            ("0.000001", "0.000001"),
            ("1e-7", "1e-7"),
            ("1e20", "100000000000000000000"),
            ("1E30", "1e+30"),
            ("1e21", "1e+21"),
            ("5e-324", "5e-324"),
            ("9007199254740993", "9007199254740993"),
            ("-1.0000000000000000001", "-1.0000000000000000001"),
            ("1234567890123456789012", "1.234567890123456789012e+21"),
            ("0.0000001234567890123456789", "1.234567890123456789e-7"),
        ] {
            assert_eq!(canonical_text(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn a_one_megabyte_number_lays_out_in_well_under_a_second() {
        let zeros = "0".repeat(1 << 20);
        for (input, expected) in [
            (format!("1.{zeros}1"), format!("1.{zeros}1")),
            (format!("1{zeros}e-{}", 1 << 20), "1".to_owned()),
            (format!("0.{zeros}5e+{}", 1 << 20), "0.5".to_owned()),
        ] {
            let started = std::time::Instant::now();
            assert_eq!(canonical_text(&input).unwrap(), expected);
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
        }
    }

    /// Decimal digits of `base^exponent × multiplier`, by schoolbook multiplication.
    fn power_digits(base: u64, exponent: u32, multiplier: u64) -> String {
        let mut little_endian = vec![1_u8];
        let mut times = |factor: u64| {
            let mut carry = 0_u128;
            for digit in &mut little_endian {
                let product = u128::from(*digit) * u128::from(factor) + carry;
                *digit = (product % 10) as u8;
                carry = product / 10;
            }
            while carry > 0 {
                little_endian.push((carry % 10) as u8);
                carry /= 10;
            }
        };
        for _ in 0..exponent {
            times(base);
        }
        times(multiplier);
        little_endian
            .iter()
            .rev()
            .map(|d| char::from(b'0' + d))
            .collect()
    }

    #[test]
    fn range_bounds_are_the_binary64_rounding_thresholds() {
        // 2^1024 − 2^970 = 2^970 × (2^54 − 1); 2^−1075 = 5^1075 / 10^1075.
        assert_eq!(OVERFLOW_DIGITS, power_digits(2, 970, (1 << 54) - 1));
        assert_eq!(OVERFLOW_DIGITS.len() as i64, OVERFLOW_N);
        assert_eq!(UNDERFLOW_DIGITS, power_digits(5, 1075, 1));
        assert_eq!(UNDERFLOW_DIGITS.len() as i64 - 1075, UNDERFLOW_N);
    }

    #[test]
    fn magnitudes_outside_binary64_and_non_json_numbers_refuse() {
        for input in [
            "1e400", "-1e400", "1e-400", "01", "1.", ".5", "+1", "NaN", "1e",
        ] {
            assert!(canonical_text(input).is_err(), "{input}");
        }
    }

    #[test]
    fn text_api_keeps_the_digits_the_value_api_rounds_and_agrees_elsewhere() {
        let exact = r#"{"amount":1234567890.123456789,"count":3,"rate":0.1}"#;
        let value: Value = serde_json::from_str(exact).unwrap();
        assert_eq!(
            canonical_text(exact).unwrap(),
            r#"{"amount":1234567890.123456789,"count":3,"rate":0.1}"#
        );
        assert_eq!(
            String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap(),
            r#"{"amount":1234567890.1234567,"count":3,"rate":0.1}"#
        );
        let shortest = r#"{"rate":0.1,"amount":1234567890.1234567,"count":3}"#;
        assert_eq!(
            canonical_json_from_bytes(shortest.as_bytes()).unwrap(),
            canonical_json_bytes(&serde_json::from_str(shortest).unwrap()).unwrap()
        );
    }

    #[test]
    fn nineteen_digit_decimal_round_trips_through_handoff_and_signing_bytes() {
        let response =
            br#"{"id":"r-1","data":{"amount":1234567890.123456789},"authoredSignatures":[]}"#;
        let handoff = canonical_response_handoff_bytes_from_json(response).unwrap();
        let reread = parse_canonical_response_handoff_bytes(&handoff).unwrap();
        assert_eq!(reread["id"], "r-1");
        let json = &handoff[RESPONSE_HANDOFF_DOMAIN.len() + 1..];
        assert_eq!(canonical_json_from_bytes(json).unwrap(), json);
        assert!(
            std::str::from_utf8(json)
                .unwrap()
                .contains("1234567890.123456789")
        );
        let signed = build_signed_payload_from_json(response, DigestAlgorithm::Sha256).unwrap();
        let signed_json =
            std::str::from_utf8(&signed.canonical_bytes[DOMAIN_SEPARATION.len() + 1..]).unwrap();
        assert_eq!(
            signed_json,
            r#"{"data":{"amount":1234567890.123456789},"id":"r-1"}"#
        );
    }

    #[test]
    fn text_api_refuses_repeated_members_non_objects_and_bad_omitted_content() {
        assert!(canonical_text(r#"{"a":1,"\u0061":2}"#).is_err());
        assert!(canonical_text(r#"[{"a":1,"a":1}]"#).is_err());
        assert!(canonical_response_handoff_bytes_from_json(b"[]").is_err());
        assert!(
            canonical_response_signed_payload_bytes_from_json(
                br#"{"authoredSignatures":[{"value":"\ud800"}]}"#
            )
            .is_err()
        );
        assert!(
            canonical_response_signed_payload_bytes_from_json(br#"{"authoredSignatures":[1e400]}"#)
                .is_err()
        );
    }
}

#[cfg(test)]
mod handoff_decode_tests {
    use super::*;

    #[test]
    fn handoff_bytes_round_trip_and_other_encodings_refuse() {
        let response = serde_json::json!({"id": "r-1", "data": {"b": 2, "a": 1}});
        let bytes = canonical_response_handoff_bytes(&response).unwrap();
        assert_eq!(
            parse_canonical_response_handoff_bytes(&bytes).unwrap(),
            response
        );
        // Bare canonical JSON, a foreign domain and non-canonical spacing all refuse.
        assert!(
            parse_canonical_response_handoff_bytes(&canonical_json_bytes(&response).unwrap())
                .is_err()
        );
        let foreign = domain_separated_canonical_bytes("formspec.other.v1", &response).unwrap();
        assert!(parse_canonical_response_handoff_bytes(&foreign).is_err());
        let mut spaced = RESPONSE_HANDOFF_DOMAIN.as_bytes().to_vec();
        spaced.push(DOMAIN_SEPARATOR_BYTE);
        spaced.extend_from_slice(br#"{ "id": "r-1", "data": {"a": 1, "b": 2} }"#);
        assert!(parse_canonical_response_handoff_bytes(&spaced).is_err());
    }
}
