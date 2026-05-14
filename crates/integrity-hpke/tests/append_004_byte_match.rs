//! Byte-exact reproduction of `append/004-hpke-wrapped-inline` HPKE wrap
//! output. Strengthens G-5 from "vectors match" to "Rust independently
//! derives the same HPKE bytes as the fixture generator" (and so as the
//! `trellis-py` stranger that replays them).
//!
//! Authority: Core §9.4 (HPKE suite 1 — RFC 9180 Base mode, X25519,
//! HKDF-SHA256, ChaCha20-Poly1305, `info = h''`, wrap `aad = h''`).
//! Fixture: `fixtures/vectors/append/004-hpke-wrapped-inline/`.
//!
//! **Gated under the `test-vectors` Cargo feature** because it exercises
//! `wrap_dek_with_pinned_ephemeral`, the Core §9.4 carve-out path. Run
//! via `cargo test -p integrity-hpke --features test-vectors`.

#![cfg(feature = "test-vectors")]
#![forbid(unsafe_code)]

use std::path::PathBuf;

use integrity_hpke::{
    HPKE_SUITE1_AAD, HPKE_SUITE1_INFO, unwrap_dek, wrap_dek_with_pinned_ephemeral,
};

/// 32-byte payload DEK pinned by `gen_append_004.py`: `00..1f`.
const PAYLOAD_DEK: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Recipient X25519 seed pinned by the fixture generator.
const RECIPIENT_SEED: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// Ephemeral X25519 seed pinned by Core §9.4 test-vector carve-out.
const EPHEMERAL_SEED: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

/// Committed HPKE encapsulated public key bytes (`derivation.md`).
const EXPECTED_EPHEMERAL_PUBKEY_HEX: &str =
    "34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847";

/// Committed HPKE-sealed DEK bytes (ciphertext || 16-byte tag).
const EXPECTED_WRAPPED_DEK_HEX: &str = "9f89d135c1594b3a52a9854609e8ac9387ec1d9a82865e8ab35fd43a2cf77028f848c833e9871ae9f43fef0b28b743fa";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn parse_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Derives a raw 32-byte X25519 public key from a seed via the HPKE crate's
/// own X25519 KEM, so the test does not need `x25519-dalek` directly.
fn x25519_pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256};
    let private = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(seed).expect("x25519 priv");
    let public = <X25519HkdfSha256 as Kem>::sk_to_pk(&private);
    let mut out = [0u8; 32];
    out.copy_from_slice(&public.to_bytes());
    out
}

#[test]
fn wrap_with_pinned_ephemeral_byte_matches_append_004_fixture() {
    let recipient_pub = x25519_pubkey_from_seed(&RECIPIENT_SEED);
    let result = wrap_dek_with_pinned_ephemeral(
        &recipient_pub,
        &EPHEMERAL_SEED,
        &PAYLOAD_DEK,
        HPKE_SUITE1_INFO,
        HPKE_SUITE1_AAD,
    )
    .expect("wrap_dek_with_pinned_ephemeral");

    let expected_eph = parse_hex(EXPECTED_EPHEMERAL_PUBKEY_HEX);
    let expected_wrapped = parse_hex(EXPECTED_WRAPPED_DEK_HEX);
    assert_eq!(
        result.ephemeral_pubkey.to_vec(),
        expected_eph,
        "ephemeral_pubkey: got {} expected {}",
        hex(&result.ephemeral_pubkey),
        EXPECTED_EPHEMERAL_PUBKEY_HEX,
    );

    let mut wire = result.ciphertext.clone();
    wire.extend_from_slice(&result.aead_tag);
    assert_eq!(
        wire,
        expected_wrapped,
        "wrapped_dek (ct||tag): got {} expected {}",
        hex(&wire),
        EXPECTED_WRAPPED_DEK_HEX,
    );
}

#[test]
fn fixture_keys_round_trip_through_unwrap() {
    let recipient_pub = x25519_pubkey_from_seed(&RECIPIENT_SEED);
    let wrap = wrap_dek_with_pinned_ephemeral(
        &recipient_pub,
        &EPHEMERAL_SEED,
        &PAYLOAD_DEK,
        HPKE_SUITE1_INFO,
        HPKE_SUITE1_AAD,
    )
    .expect("wrap");

    let mut wire = wrap.ciphertext.clone();
    wire.extend_from_slice(&wrap.aead_tag);

    let plaintext = unwrap_dek(
        &RECIPIENT_SEED,
        &wrap.ephemeral_pubkey,
        &wire,
        HPKE_SUITE1_INFO,
        HPKE_SUITE1_AAD,
    )
    .expect("unwrap");
    assert_eq!(plaintext, PAYLOAD_DEK.to_vec());
}

/// Sanity: the committed `KeyBagEntry.wrapped_dek` from the fixture itself
/// (loaded directly off disk) decrypts under the recipient's pinned key.
/// This guards against silent fixture / spec / Rust drift in either direction.
#[test]
fn committed_fixture_wrapped_dek_unwraps_to_pinned_dek() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/integrity-hpke -> crates
    path.pop(); // crates -> integrity-stack
    path.pop(); // integrity-stack -> formspec-stack
    path.push("trellis");
    path.push("fixtures/vectors/append/004-hpke-wrapped-inline/expected-event-payload.cbor");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

    let (eph_pubkey, wrapped_dek) = extract_keybag_entry_0(&bytes)
        .unwrap_or_else(|e| panic!("extract key_bag.entries[0] from {path:?}: {e}"));

    assert_eq!(hex(&eph_pubkey), EXPECTED_EPHEMERAL_PUBKEY_HEX);
    assert_eq!(hex(&wrapped_dek), EXPECTED_WRAPPED_DEK_HEX);

    let plaintext = unwrap_dek(
        &RECIPIENT_SEED,
        eph_pubkey
            .as_slice()
            .try_into()
            .expect("32-byte ephemeral_pubkey"),
        &wrapped_dek,
        HPKE_SUITE1_INFO,
        HPKE_SUITE1_AAD,
    )
    .expect("unwrap committed fixture wrapped_dek");
    assert_eq!(plaintext, PAYLOAD_DEK.to_vec());
}

/// Tiny dCBOR-aware extractor for `key_bag.entries[0].{ephemeral_pubkey,wrapped_dek}`
/// in the committed `expected-event-payload.cbor`. We avoid pulling a CBOR
/// dependency by walking the bytes for the two named text-string keys; the
/// values immediately after each name are byte-strings whose lengths we read
/// out of the major-type-2 header.
fn extract_keybag_entry_0(cbor: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let eph = find_named_bstr(cbor, b"ephemeral_pubkey")
        .ok_or_else(|| "ephemeral_pubkey not found".to_string())?;
    let wrapped =
        find_named_bstr(cbor, b"wrapped_dek").ok_or_else(|| "wrapped_dek not found".to_string())?;
    Ok((eph, wrapped))
}

fn find_named_bstr(cbor: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    // Look for a CBOR text string whose payload equals `name`. dCBOR tstr
    // headers for short keys are 0x60 + len (len ∈ 0..=23), or 0x78 followed
    // by 1-byte length (len ∈ 24..=255). The longest key here is 16 bytes,
    // both inside the short branch.
    let n = name.len();
    if n > 23 {
        return None;
    }
    let header = 0x60u8 | (n as u8);
    let mut i = 0;
    while i + 1 + n < cbor.len() {
        if cbor[i] == header && &cbor[i + 1..i + 1 + n] == name {
            // Value follows immediately; expect a major-type-2 byte string.
            let v = i + 1 + n;
            return read_bstr(cbor, v);
        }
        i += 1;
    }
    None
}

fn read_bstr(cbor: &[u8], at: usize) -> Option<Vec<u8>> {
    let head = *cbor.get(at)?;
    if head >> 5 != 2 {
        return None;
    }
    let arg = head & 0x1f;
    let (len, body_start) = match arg {
        0..=23 => (arg as usize, at + 1),
        24 => (*cbor.get(at + 1)? as usize, at + 2),
        25 => {
            let mut buf = [0u8; 2];
            buf.copy_from_slice(cbor.get(at + 1..at + 3)?);
            (u16::from_be_bytes(buf) as usize, at + 3)
        }
        26 => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(cbor.get(at + 1..at + 5)?);
            (u32::from_be_bytes(buf) as usize, at + 5)
        }
        _ => return None,
    };
    cbor.get(body_start..body_start + len).map(|s| s.to_vec())
}
