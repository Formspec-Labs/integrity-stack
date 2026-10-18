// Rust guideline compliant 2026-02-21
//! The `integrity-canonical-json-v1` writer: RFC 8785 with exact decimal numbers.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::DOMAIN_SEPARATOR_BYTE;

/// Serializes an in-process JSON value under `integrity-canonical-json-v1`.
///
/// Exact for the numbers `value` holds. A `Value` parsed from JSON text already
/// holds `f64` numbers, so commit to such text with [`canonical_json_from_bytes`]
/// instead; Formspec Responses go through [`crate::ResponseJson`].
///
/// # Errors
///
/// Returns an error when a number lies outside the binary64 range.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// Builds `domain || NUL || canonical-json(value)` for an in-process value.
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

/// Canonicalizes JSON text under `integrity-canonical-json-v1`.
///
/// Numbers are read as text, so nothing passes through `f64`.
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

pub(crate) fn parse_raw(input: &[u8]) -> Result<&RawValue, String> {
    serde_json::from_slice(input).map_err(|error| format!("input is not valid JSON: {error}"))
}

pub(crate) fn members(object: &str) -> Result<Vec<(String, &RawValue)>, String> {
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

pub(crate) fn write_members(
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

#[cfg(test)]
mod exact_number_tests {
    use super::*;
    use serde_json::Value;

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
}
