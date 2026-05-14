// Rust guideline compliant 2026-02-21
//! Shared CBOR and byte helpers for integrity crates.
//!
//! The crate defaults to `std` while keeping its public helpers usable from
//! `alloc`-backed no-std builds when default features are disabled. It owns
//! only generic CBOR encoding, CBOR map lookup, and byte-digest operations;
//! profile-specific labels and domain tags belong in their profile crates.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

/// Re-exports `ciborium::Value` for shared CBOR helpers.
pub use ciborium::Value;

/// Error returned by shared CBOR map lookup helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CborHelperError(pub String);

impl fmt::Display for CborHelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CborHelperError {}

/// Encodes a CBOR byte string.
#[must_use]
pub fn encode_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = encode_major_len(2, bytes.len() as u64);
    encoded.extend_from_slice(bytes);
    encoded
}

/// Encodes a CBOR text string.
#[must_use]
pub fn encode_tstr(text: &str) -> Vec<u8> {
    let mut encoded = encode_major_len(3, text.len() as u64);
    encoded.extend_from_slice(text.as_bytes());
    encoded
}

/// Encodes a CBOR unsigned integer.
#[must_use]
pub fn encode_uint(value: u64) -> Vec<u8> {
    encode_major_len(0, value)
}

/// Encodes a CBOR negative integer.
///
/// The input is the unsigned magnitude `n` for the CBOR integer `-1 - n`.
/// For example, `n == 7` yields `-8`.
#[must_use]
pub fn encode_cbor_negative_int(n: u64) -> Vec<u8> {
    encode_major_len(1, n)
}

/// Computes a domain-separated SHA-256 digest.
///
/// The preimage is the big-endian byte length of `tag`, followed by the tag
/// bytes, followed by the big-endian byte length of `component`, followed by
/// the component bytes.
#[must_use]
pub fn domain_separated_sha256(tag: &str, component: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((tag.len() as u32).to_be_bytes());
    hasher.update(tag.as_bytes());
    hasher.update((component.len() as u32).to_be_bytes());
    hasher.update(component);
    hasher.finalize().into()
}

/// Computes the SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Decodes `bytes` as a single CBOR value.
///
/// # Errors
/// Returns an error if `bytes` is not exactly one decodable CBOR value.
pub fn decode_cbor_value(bytes: &[u8]) -> Result<Value, CborHelperError> {
    let mut reader = bytes;
    let value = ciborium::from_reader(&mut reader)
        .map_err(|error| CborHelperError(format!("failed to decode CBOR: {error}")))?;
    if !reader.is_empty() {
        return Err(CborHelperError(
            "trailing bytes after CBOR value".to_owned(),
        ));
    }
    Ok(value)
}

/// Performs a case-sensitive map lookup for a text key.
#[must_use]
pub fn map_lookup_optional_value<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Option<&'a Value> {
    map.iter()
        .find(|(key, _)| key.as_text().is_some_and(|text| text == key_name))
        .map(|(_, value)| value)
}

/// Performs a required case-sensitive text-key map lookup.
///
/// # Errors
/// Returns an error when the requested key is absent.
pub fn map_lookup_value<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Result<&'a Value, CborHelperError> {
    map_lookup_optional_value(map, key_name)
        .ok_or_else(|| CborHelperError(format!("missing `{key_name}` value")))
}

/// Looks up a byte string field in a map.
///
/// # Errors
/// Returns an error when the field is missing or is not a byte string.
pub fn map_lookup_bytes(
    map: &[(Value, Value)],
    key_name: &str,
) -> Result<Vec<u8>, CborHelperError> {
    map_lookup_value(map, key_name).and_then(|value| {
        value
            .as_bytes()
            .cloned()
            .ok_or_else(|| CborHelperError(format!("`{key_name}` is not a byte string")))
    })
}

/// Looks up a fixed-length byte string field in a map.
///
/// # Errors
/// Returns an error when the field is missing, non-bytes, or wrongly sized.
pub fn map_lookup_fixed_bytes(
    map: &[(Value, Value)],
    key_name: &str,
    expected_len: usize,
) -> Result<Vec<u8>, CborHelperError> {
    let bytes = map_lookup_bytes(map, key_name)?;
    if bytes.len() != expected_len {
        return Err(CborHelperError(format!(
            "`{key_name}` must be {expected_len} bytes"
        )));
    }
    Ok(bytes)
}

/// Looks up an optional byte string field in a map.
///
/// # Errors
/// Returns an error when the field is present but neither bytes nor null.
pub fn map_lookup_optional_bytes(
    map: &[(Value, Value)],
    key_name: &str,
) -> Result<Option<Vec<u8>>, CborHelperError> {
    match map_lookup_optional_value(map, key_name) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(CborHelperError(format!(
            "`{key_name}` is neither bytes nor null"
        ))),
    }
}

/// Looks up an optional fixed-length byte string field in a map.
///
/// # Errors
/// Returns an error when the present field is non-bytes or wrongly sized.
pub fn map_lookup_optional_fixed_bytes(
    map: &[(Value, Value)],
    key_name: &str,
    expected_len: usize,
) -> Result<Option<Vec<u8>>, CborHelperError> {
    match map_lookup_optional_bytes(map, key_name)? {
        Some(bytes) if bytes.len() == expected_len => Ok(Some(bytes)),
        Some(_) => Err(CborHelperError(format!(
            "`{key_name}` must be {expected_len} bytes"
        ))),
        None => Ok(None),
    }
}

/// Looks up an unsigned integer field in a map.
///
/// # Errors
/// Returns an error when the field is missing or is not unsigned.
pub fn map_lookup_u64(map: &[(Value, Value)], key_name: &str) -> Result<u64, CborHelperError> {
    let value = map_lookup_value(map, key_name)?;
    value
        .as_integer()
        .and_then(|integer| integer.try_into().ok())
        .ok_or_else(|| CborHelperError(format!("`{key_name}` is not an unsigned integer")))
}

/// Looks up a boolean field in a map.
///
/// # Errors
/// Returns an error when the field is missing or is not a boolean.
pub fn map_lookup_bool(map: &[(Value, Value)], key_name: &str) -> Result<bool, CborHelperError> {
    map_lookup_value(map, key_name).and_then(|value| {
        value
            .as_bool()
            .ok_or_else(|| CborHelperError(format!("`{key_name}` is not a boolean")))
    })
}

/// Looks up a text string field in a map.
///
/// # Errors
/// Returns an error when the field is missing or is not text.
pub fn map_lookup_text(map: &[(Value, Value)], key_name: &str) -> Result<String, CborHelperError> {
    map_lookup_value(map, key_name).and_then(|value| {
        value
            .as_text()
            .map(ToOwned::to_owned)
            .ok_or_else(|| CborHelperError(format!("`{key_name}` is not a text string")))
    })
}

/// Looks up an optional text string field in a map.
///
/// # Errors
/// Returns an error when the field is present but neither text nor null.
pub fn map_lookup_optional_text(
    map: &[(Value, Value)],
    key_name: &str,
) -> Result<Option<String>, CborHelperError> {
    match map_lookup_optional_value(map, key_name) {
        Some(Value::Text(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(CborHelperError(format!(
            "`{key_name}` is neither text nor null"
        ))),
    }
}

/// Looks up a map field in a map.
///
/// # Errors
/// Returns an error when the field is missing or is not a map.
pub fn map_lookup_map<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Result<&'a [(Value, Value)], CborHelperError> {
    map_lookup_value(map, key_name).and_then(|value| {
        value
            .as_map()
            .map(Vec::as_slice)
            .ok_or_else(|| CborHelperError(format!("`{key_name}` is not a map")))
    })
}

/// Looks up an optional map field in a map.
///
/// # Errors
/// Returns an error when the field is present but is not a map.
pub fn map_lookup_optional_map<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Result<Option<&'a [(Value, Value)]>, CborHelperError> {
    match map_lookup_optional_value(map, key_name) {
        Some(Value::Null) | None => Ok(None),
        Some(value) => value
            .as_map()
            .map(Vec::as_slice)
            .map(Some)
            .ok_or_else(|| CborHelperError(format!("`{key_name}` is not a map"))),
    }
}

/// Looks up an array field in a map.
///
/// # Errors
/// Returns an error when the field is missing or is not an array.
pub fn map_lookup_array<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Result<&'a [Value], CborHelperError> {
    map_lookup_value(map, key_name).and_then(|value| {
        value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| CborHelperError(format!("`{key_name}` is not an array")))
    })
}

/// Performs a map lookup for an integer label.
#[must_use]
pub fn map_lookup_integer_label_value(map: &[(Value, Value)], label: i128) -> Option<&Value> {
    map.iter()
        .find(|(key, _)| {
            key.as_integer()
                .is_some_and(|value| i128::from(value) == label)
        })
        .map(|(_, value)| value)
}

/// Looks up an integer-labeled byte string field in a map.
///
/// # Errors
/// Returns an error when the label is missing or does not contain bytes.
pub fn map_lookup_integer_label_bytes(
    map: &[(Value, Value)],
    label: i128,
) -> Result<Vec<u8>, CborHelperError> {
    map_lookup_integer_label_value(map, label)
        .and_then(|value| value.as_bytes().cloned())
        .ok_or_else(|| CborHelperError(format!("missing COSE label {label} bytes")))
}

fn encode_major_len(major: u8, value: u64) -> Vec<u8> {
    let header = major << 5;
    match value {
        0..=23 => vec![header | value as u8],
        24..=0xff => vec![header | 24, value as u8],
        0x100..=0xffff => {
            let mut encoded = vec![header | 25];
            encoded.extend_from_slice(&(value as u16).to_be_bytes());
            encoded
        }
        0x1_0000..=0xffff_ffff => {
            let mut encoded = vec![header | 26];
            encoded.extend_from_slice(&(value as u32).to_be_bytes());
            encoded
        }
        _ => {
            let mut encoded = vec![header | 27];
            encoded.extend_from_slice(&value.to_be_bytes());
            encoded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_cbor_value, domain_separated_sha256, encode_bstr, encode_cbor_negative_int,
        encode_tstr, encode_uint, map_lookup_fixed_bytes, map_lookup_text, map_lookup_u64,
        sha256_bytes,
    };

    #[test]
    fn encode_uint_uses_canonical_widths() {
        assert_eq!(encode_uint(1), vec![0x01]);
        assert_eq!(encode_uint(24), vec![0x18, 0x18]);
        assert_eq!(encode_uint(256), vec![0x19, 0x01, 0x00]);
    }

    #[test]
    fn encode_bstr_and_tstr_include_major_type_headers() {
        assert_eq!(encode_bstr(b"abc"), vec![0x43, b'a', b'b', b'c']);
        assert_eq!(encode_tstr("abc"), vec![0x63, b'a', b'b', b'c']);
    }

    #[test]
    fn encode_cbor_negative_int_uses_unsigned_magnitude() {
        assert_eq!(encode_cbor_negative_int(7), vec![0x27]);
        assert_eq!(
            encode_cbor_negative_int(65_536),
            vec![0x3a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn decode_and_lookup_helpers_read_text_keyed_maps() {
        let bytes = [
            0xa3, 0x64, b'n', b'a', b'm', b'e', 0x65, b'a', b'l', b'p', b'h', b'a', 0x65, b'c',
            b'o', b'u', b'n', b't', 0x18, 0x2a, 0x66, b'd', b'i', b'g', b'e', b's', b't', 0x42,
            0xaa, 0xbb,
        ];
        let value = decode_cbor_value(&bytes).expect("valid CBOR map");
        let map = value.as_map().expect("value is a map");

        assert_eq!(map_lookup_text(map, "name").unwrap(), "alpha");
        assert_eq!(map_lookup_u64(map, "count").unwrap(), 42);
        assert_eq!(
            map_lookup_fixed_bytes(map, "digest", 2).unwrap(),
            vec![0xaa, 0xbb]
        );
    }

    #[test]
    fn decode_cbor_value_rejects_trailing_bytes() {
        let err = decode_cbor_value(&[0x01, 0x02]).expect_err("trailing value must reject");

        assert!(
            err.to_string().contains("trailing bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sha256_bytes_matches_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn domain_separated_sha256_changes_with_tag() {
        let first = domain_separated_sha256("first", b"payload");
        let second = domain_separated_sha256("second", b"payload");

        assert_ne!(first, second);
    }
}
