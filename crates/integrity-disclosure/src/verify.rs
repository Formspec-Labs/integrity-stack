// Rust guideline compliant 2026-02-21

//! Offline verification of a presentation against a pinned `(iss, kid, key)`.

use std::collections::HashSet;

use integrity_cose::verify_ed25519_signature;
use serde_json::{Map, Value};

use crate::error::{DisclosureError, ErrorCode, Result};
use crate::issue::ALG_EDDSA;
use crate::wire::{
    MAX_DISCLOSURES, MAX_PATH_BYTES, MAX_PRESENTATION_BYTES, MAX_SD_DIGESTS, SALT_BYTES, SD_ALG,
    Scan, b64_decode, disclosure_digest, is_digest, is_reserved_name, jcs, parse_json, scan_value,
};

/// What a relying party pins about an issuer, from the agency's own publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerPin {
    /// Expected payload `iss`.
    pub iss: String,
    /// Expected header `kid`. Pins in one call must have distinct `kid`s.
    pub kid: String,
    /// Ed25519 public key for `(iss, kid)`.
    pub public_key: [u8; 32],
}

/// How strictly disclosure encodings are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// This stack's profile: header, payload and every disclosure are JCS, and every salt is 128
    /// bits. Use for presentations this stack issued.
    Pinned,
    /// Any RFC 9901 encoding (whitespace, key order, any salt length), still restricted to flat
    /// object-property disclosures. Use for other issuers and for RFC examples. Values are
    /// normalised: `value_jcs` is the JCS of the parsed value, not the issuer's original text.
    /// The viewer and CLI paths must use [`Encoding::Pinned`], where it is the committed text.
    Rfc9901,
}

/// Verifier inputs besides the presentation and pins.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions<'a> {
    /// Required JWT `typ`, for example `formspec-response+sd-jwt`.
    pub expected_typ: &'a str,
    /// Encoding strictness.
    pub encoding: Encoding,
}

/// One verified disclosed claim.
#[derive(Debug, Clone, PartialEq)]
pub struct DisclosedClaim {
    /// Claim path, the disclosure's claim name.
    pub path: String,
    /// Parsed value.
    pub value: Value,
    /// JCS text of the value. Show this, never a re-serialization of `value`: JCS numbers are
    /// IEEE doubles. With [`Encoding::Pinned`] it is exactly the committed text; with
    /// [`Encoding::Rfc9901`] it is a normalisation of what the issuer wrote.
    pub value_jcs: String,
}

/// A presentation that passed every check.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// Pinned issuer.
    pub iss: String,
    /// Key identifier that verified.
    pub kid: String,
    /// Always-visible payload claims, without `iss`, `_sd` and `_sd_alg`.
    pub public_claims: Map<String, Value>,
    /// Disclosed claims in presentation order.
    pub disclosed: Vec<DisclosedClaim>,
}

fn fail<T>(code: ErrorCode, message: &str) -> Result<T> {
    Err(DisclosureError::new(code, message))
}

fn decode_text(segment: &str) -> Result<String> {
    String::from_utf8(b64_decode(segment)?)
        .map_err(|_| DisclosureError::new(ErrorCode::MalformedJson, "segment is not UTF-8"))
}

fn jwt_parts(jwt: &str) -> Result<[&str; 3]> {
    let mut parts = jwt.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok([h, p, s])
        }
        _ => fail(
            ErrorCode::MalformedCompact,
            "JWT is not header.payload.signature",
        ),
    }
}

/// Reads the `_sd` digests of a JWT without verifying it. Never trust the result for a decision.
pub(crate) fn jwt_sd_digests(jwt: &str) -> Result<HashSet<String>> {
    let [_, payload, _] = jwt_parts(jwt)?;
    let payload = parse_json(&decode_text(payload)?)?;
    sd_digests(&payload)
}

fn sd_digests(payload: &Value) -> Result<HashSet<String>> {
    let Some(Value::Array(list)) = payload.get("_sd") else {
        return fail(ErrorCode::MalformedSd, "_sd is missing or not an array");
    };
    if list.len() > MAX_SD_DIGESTS {
        return fail(
            ErrorCode::InputTooLarge,
            "_sd is longer than MAX_SD_DIGESTS",
        );
    }
    let mut digests = HashSet::with_capacity(list.len());
    for entry in list {
        let Some(digest) = entry.as_str().filter(|d| is_digest(d)) else {
            return fail(ErrorCode::MalformedSd, "_sd holds a malformed digest");
        };
        if !digests.insert(digest.to_owned()) {
            return fail(ErrorCode::DuplicateDigest, "_sd repeats a digest");
        }
    }
    Ok(digests)
}

/// True when a nested object anywhere below the top level has RFC 9901 structure keys.
fn nested_structure(value: &Value) -> bool {
    scan_value(value, 0) != Scan::Clean
}

/// Verifies an SD-JWT presentation offline.
///
/// In order, and failing closed on the first problem:
/// 1. size and shape of `jwt~d1~...~`; a trailing key-binding JWT is refused;
/// 2. header is exactly `{alg: "EdDSA", typ, kid}` and `kid` selects one pin;
/// 3. the Ed25519 signature over `b64(header).b64(payload)` verifies under that pin;
/// 4. `iss` equals the pin's `iss`; `_sd_alg` is `sha-256`; `_sd` holds unique digests;
/// 5. each disclosure's digest is in `_sd`, no digest or path repeats, no path collides with a
///    payload claim, and (pinned encoding) each is canonical with a 128-bit salt.
///
/// Time claims (`exp`, `nbf`) are not interpreted: freshness is the relying party's policy.
///
/// # Errors
///
/// Returns an [`ErrorCode`] naming the first failed rule.
pub fn verify(
    presentation: &str,
    pins: &[IssuerPin],
    options: &VerifyOptions<'_>,
) -> Result<Verified> {
    if presentation.len() > MAX_PRESENTATION_BYTES {
        return fail(
            ErrorCode::InputTooLarge,
            "presentation exceeds MAX_PRESENTATION_BYTES",
        );
    }
    if !presentation
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
    {
        return fail(
            ErrorCode::MalformedCompact,
            "presentation has a non-compact character",
        );
    }
    let mut segments = presentation.split('~');
    let jwt = segments.next().unwrap_or_default();
    // Bound the work before collecting: at most MAX_DISCLOSURES segments plus the trailing empty
    // one may follow the JWT.
    let mut tail: Vec<&str> = segments.by_ref().take(MAX_DISCLOSURES + 1).collect();
    if segments.next().is_some() {
        return fail(
            ErrorCode::InputTooLarge,
            "more disclosures than MAX_DISCLOSURES",
        );
    }
    // `jwt~d1~...~` ends in an empty segment; a non-empty last segment is a key-binding JWT or a
    // missing tilde, and the bearer profile accepts neither.
    if tail.pop() != Some("") {
        return fail(ErrorCode::MalformedCompact, "presentation must end with ~");
    }
    if tail.len() > MAX_DISCLOSURES {
        return fail(
            ErrorCode::InputTooLarge,
            "more disclosures than MAX_DISCLOSURES",
        );
    }
    if tail.iter().any(|d| d.is_empty()) {
        return fail(ErrorCode::MalformedCompact, "empty disclosure segment");
    }

    let [header_b64, payload_b64, signature_b64] = jwt_parts(jwt)?;
    let strict = options.encoding == Encoding::Pinned;

    let header_text = decode_text(header_b64)?;
    let header = parse_json(&header_text)?;
    if strict {
        require_canonical(
            &header,
            header_text.as_bytes(),
            ErrorCode::UnsupportedHeader,
        )?;
    }
    let kid = check_header(&header, options.expected_typ)?;

    let pin = select_pin(pins, kid)?;

    let signature: [u8; 64] = b64_decode(signature_b64)?
        .try_into()
        .map_err(|_| DisclosureError::new(ErrorCode::BadSignature, "signature is not 64 bytes"))?;
    let signing_input = &jwt[..header_b64.len() + 1 + payload_b64.len()];
    if !verify_ed25519_signature(pin.public_key, signing_input.as_bytes(), signature) {
        return fail(
            ErrorCode::BadSignature,
            "signature does not verify under the pinned key",
        );
    }

    let payload_text = decode_text(payload_b64)?;
    let payload = parse_json(&payload_text)?;
    if strict {
        require_canonical(&payload, payload_text.as_bytes(), ErrorCode::MalformedJson)?;
    }
    let Value::Object(payload) = payload else {
        return fail(ErrorCode::MalformedJson, "payload is not an object");
    };
    if payload.get("iss").and_then(Value::as_str) != Some(pin.iss.as_str()) {
        return fail(ErrorCode::WrongIssuer, "iss is not the pinned issuer");
    }
    match payload.get("_sd_alg") {
        Some(Value::String(alg)) if alg == SD_ALG => {}
        None if !strict => {}
        _ => return fail(ErrorCode::UnsupportedSdAlg, "_sd_alg is not sha-256"),
    }
    if payload.contains_key("cnf") || payload.contains_key("...") {
        return fail(
            ErrorCode::UnsupportedStructure,
            "key binding is not supported",
        );
    }
    for (name, value) in &payload {
        if name != "_sd" && nested_structure(value) {
            return fail(ErrorCode::UnsupportedStructure, "payload nests _sd or ...");
        }
    }
    let listed = sd_digests(&Value::Object(payload.clone()))?;

    let mut seen_digests: HashSet<String> = HashSet::with_capacity(tail.len());
    let mut seen_paths: HashSet<String> = HashSet::with_capacity(tail.len());
    let mut disclosed = Vec::with_capacity(tail.len());
    for encoded in tail {
        let digest = disclosure_digest(encoded);
        if !listed.contains(&digest) {
            return fail(
                ErrorCode::UnknownDigest,
                "a disclosure digest is not in _sd",
            );
        }
        if !seen_digests.insert(digest) {
            return fail(
                ErrorCode::DuplicateDisclosure,
                "a disclosure is presented twice",
            );
        }
        let claim = parse_disclosure(encoded, strict)?;
        if claim.path.is_empty()
            || claim.path.len() > MAX_PATH_BYTES
            || is_reserved_name(&claim.path)
            || payload.contains_key(&claim.path)
        {
            return fail(
                ErrorCode::ReservedClaimName,
                "a path collides with a payload claim",
            );
        }
        if !seen_paths.insert(claim.path.clone()) {
            return fail(
                ErrorCode::DuplicatePath,
                "two disclosures name the same path",
            );
        }
        disclosed.push(claim);
    }

    let mut public_claims = payload;
    for name in ["iss", "_sd", "_sd_alg"] {
        public_claims.remove(name);
    }
    Ok(Verified {
        iss: pin.iss.clone(),
        kid: pin.kid.clone(),
        public_claims,
        disclosed,
    })
}

fn require_canonical(value: &Value, text: &[u8], code: ErrorCode) -> Result<()> {
    if jcs(value)? == text {
        Ok(())
    } else {
        fail(code, "not canonical (JCS) JSON")
    }
}

fn check_header<'a>(header: &'a Value, expected_typ: &str) -> Result<&'a str> {
    let Value::Object(map) = header else {
        return fail(ErrorCode::UnsupportedHeader, "header is not an object");
    };
    if map.len() != 3 {
        return fail(
            ErrorCode::UnsupportedHeader,
            "header must be exactly alg, typ, kid",
        );
    }
    let field = |name: &str| map.get(name).and_then(Value::as_str);
    match (field("alg"), field("typ"), field("kid")) {
        (Some(ALG_EDDSA), Some(typ), Some(kid)) if typ == expected_typ && !kid.is_empty() => {
            Ok(kid)
        }
        _ => fail(
            ErrorCode::UnsupportedHeader,
            "header alg, typ or kid is not accepted",
        ),
    }
}

fn select_pin<'a>(pins: &'a [IssuerPin], kid: &str) -> Result<&'a IssuerPin> {
    let mut seen = HashSet::with_capacity(pins.len());
    if !pins.iter().all(|pin| seen.insert(pin.kid.as_str())) {
        return fail(ErrorCode::AmbiguousPins, "two pins share a kid");
    }
    pins.iter()
        .find(|pin| pin.kid == kid)
        .ok_or_else(|| DisclosureError::new(ErrorCode::UnknownKey, "no pin for this kid"))
}

/// Decodes and shapes one disclosure; the caller has already matched its digest to `_sd`.
fn parse_disclosure(encoded: &str, strict: bool) -> Result<DisclosedClaim> {
    let bytes = b64_decode(encoded)?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| DisclosureError::new(ErrorCode::MalformedDisclosure, "not UTF-8"))?;
    let Value::Array(items) = parse_json(&text)? else {
        return fail(ErrorCode::MalformedDisclosure, "disclosure is not an array");
    };
    let [salt, path, value] = match <[Value; 3]>::try_from(items) {
        Ok(triple) => triple,
        Err(items) if items.len() == 2 => {
            return fail(
                ErrorCode::UnsupportedStructure,
                "array-element disclosures are not supported",
            );
        }
        Err(_) => {
            return fail(
                ErrorCode::MalformedDisclosure,
                "disclosure is not [salt, name, value]",
            );
        }
    };
    let (Value::String(salt), Value::String(path)) = (&salt, &path) else {
        return fail(
            ErrorCode::MalformedDisclosure,
            "salt and name must be strings",
        );
    };
    if nested_structure(&value) {
        return fail(
            ErrorCode::UnsupportedStructure,
            "disclosed value nests _sd or ...",
        );
    }
    let value_jcs = String::from_utf8(jcs(&value)?)
        .map_err(|_| DisclosureError::new(ErrorCode::MalformedJson, "JCS is not UTF-8"))?;
    if strict {
        let repacked = Value::Array(vec![
            Value::String(salt.clone()),
            Value::String(path.clone()),
            value.clone(),
        ]);
        if jcs(&repacked)? != bytes {
            return fail(
                ErrorCode::NonCanonicalDisclosure,
                "disclosure is not JCS([salt, path, value])",
            );
        }
        if !matches!(b64_decode(salt), Ok(raw) if raw.len() == SALT_BYTES) {
            return fail(ErrorCode::WeakSalt, "salt is not exactly 128 bits");
        }
    }
    Ok(DisclosedClaim {
        path: path.clone(),
        value,
        value_jcs,
    })
}
