// Rust guideline compliant 2026-04-27
//! HPKE Base-mode wrap/unwrap for `KeyBagEntry` (Trellis Core §9.4 suite 1).
//!
//! Suite 1 = RFC 9180 Base mode with
//! `KEM = DHKEM(X25519, HKDF-SHA256)` (id `0x0020`),
//! `KDF = HKDF-SHA256` (id `0x0001`),
//! `AEAD = ChaCha20-Poly1305` (id `0x0003`).
//! Per Core §9.4 the Phase-1 production paths pin `info = h''` and wrap
//! `aad = h''`, but the [`HPKE_SUITE1_INFO`] / [`HPKE_SUITE1_AAD`] constants
//! are public so callers spell out the empty values explicitly at call
//! sites — guarding against future suites that allow non-empty values.
//!
//! ## Three call shapes
//!
//! - [`wrap_dek`] — production seal. Generates a fresh X25519 ephemeral
//!   keypair through [`integrity_seam::SecureRandom`], runs RFC 9180 Base
//!   encap, and ChaCha20-Poly1305 seals the DEK. Goes through
//!   `hpke::single_shot_seal`.
//!
//! - `wrap_dek_with_pinned_ephemeral` — fixture-only seal, **gated behind
//!   the `test-vectors` Cargo feature**. The Trellis fixture corpus uses
//!   pinned 32-byte X25519 scalars as ephemeral private keys (Core §9.4
//!   test-vector carve-out), so byte-equal reproducibility across
//!   implementations does not depend on a CSPRNG. The standard
//!   `hpke::setup_sender` path runs `DeriveKeyPair(GenerateRandomBytes())`
//!   (RFC 9180 §7.1) and so cannot accept a raw scalar as ephemeral. This
//!   function therefore hand-rolls RFC 9180 §5.1.1 Encap on top of
//!   [`x25519_dalek`] + the (`#[doc(hidden)]` but `pub`)
//!   `hpke::kdf::extract_and_expand` / `hpke::kdf::labeled_extract`
//!   helpers, then completes the key-schedule via the same helpers and
//!   AEAD-seals with `chacha20poly1305::ChaCha20Poly1305`. The receiver
//!   side is unchanged — `setup_receiver` (per [`unwrap_dek`]) reproduces
//!   the same shared secret from `enc + sk_recip` regardless of how the
//!   sender chose `sk_eph`. The feature gate is the production-graph
//!   firewall: a binary built without `--features test-vectors` cannot
//!   link the carve-out path even by mistake. Re-enable for byte-oracle
//!   replays via `cargo nextest run -p trellis-hpke --features test-vectors`.
//!
//! - [`unwrap_dek`] — production / verifier open. Constructs the
//!   `X25519HkdfSha256` private key from a 32-byte recipient seed, then
//!   `setup_receiver` + `AeadCtxR::open` to recover the DEK plaintext.

#![forbid(unsafe_code)]

use hpke::{
    Deserializable, OpModeR, Serializable, aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
};
use integrity_seam::SecureRandom;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "test-vectors")]
use chacha20poly1305::{
    AeadInPlace, ChaCha20Poly1305, KeyInit, aead::generic_array::GenericArray as AeadGenericArray,
};
#[cfg(feature = "test-vectors")]
use hpke::kdf::{LabeledExpand, extract_and_expand, labeled_extract};
#[cfg(feature = "test-vectors")]
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Static};

/// HPKE `info` for Trellis Phase-1 suite 1 wraps (Core §9.4: empty).
pub const HPKE_SUITE1_INFO: &[u8] = &[];

/// HPKE wrap `aad` for Trellis Phase-1 suite 1 wraps (Core §9.4: empty).
pub const HPKE_SUITE1_AAD: &[u8] = &[];

#[cfg(feature = "test-vectors")]
const KEM_SUITE_ID: [u8; 5] = [b'K', b'E', b'M', 0x00, 0x20]; // "KEM" || 0x0020
/// HPKE suite-id binding string `"HPKE" || KEM_ID || KDF_ID || AEAD_ID`
/// (RFC 9180 §5.1) for X25519-HKDF-SHA256-ChaCha20Poly1305.
#[cfg(feature = "test-vectors")]
const HPKE_SUITE_ID: [u8; 10] = [b'H', b'P', b'K', b'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x03];

const POLY1305_TAG_LEN: usize = 16;

struct SecureRandomRng<'a> {
    source: &'a dyn SecureRandom,
    error: Option<String>,
}

impl<'a> SecureRandomRng<'a> {
    fn new(source: &'a dyn SecureRandom) -> Self {
        Self {
            source,
            error: None,
        }
    }

    fn take_error(&mut self) -> Option<String> {
        self.error.take()
    }
}

impl RngCore for SecureRandomRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.error.is_some() {
            dest.fill(0);
            return;
        }
        if let Err(error) = self.source.fill_bytes(dest) {
            self.error = Some(error.to_string());
            dest.fill(0);
        }
    }
}

impl CryptoRng for SecureRandomRng<'_> {}

/// Successful Phase-1 wrap output. Wire encoding for `KeyBagEntry` is
/// `ephemeral_pubkey` and (`ciphertext` || `aead_tag`) as `wrapped_dek`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapResult {
    /// HPKE encapsulated public key (`enc`) — the X25519 ephemeral public key.
    pub ephemeral_pubkey: [u8; 32],
    /// AEAD ciphertext (no tag).
    pub ciphertext: Vec<u8>,
    /// 16-byte ChaCha20-Poly1305 authentication tag.
    pub aead_tag: [u8; 16],
}

/// HPKE wrap/unwrap failure modes.
#[derive(Debug)]
pub enum HpkeError {
    /// Inputs failed structural validation (wrong length, malformed key).
    InvalidInput(&'static str),
    /// Underlying `hpke` crate error (encap / decap / seal / open).
    Crate(hpke::HpkeError),
    /// Randomness source failed.
    Random(String),
    /// AEAD authentication failed (key/tag/aad mismatch).
    AeadFailure,
    /// HKDF or KDF helper rejected its arguments.
    Kdf(&'static str),
}

impl std::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(why) => write!(f, "invalid HPKE input: {why}"),
            Self::Crate(err) => write!(f, "hpke crate error: {err:?}"),
            Self::Random(err) => write!(f, "randomness failure: {err}"),
            Self::AeadFailure => write!(f, "AEAD authentication failed"),
            Self::Kdf(why) => write!(f, "KDF failure: {why}"),
        }
    }
}

impl std::error::Error for HpkeError {}

impl From<hpke::HpkeError> for HpkeError {
    fn from(value: hpke::HpkeError) -> Self {
        Self::Crate(value)
    }
}

/// Production seal — generates a fresh X25519 ephemeral via `rng`.
///
/// Phase 1 callers pass [`HPKE_SUITE1_INFO`] and [`HPKE_SUITE1_AAD`] for
/// the `info` / `aad` parameters per Core §9.4.
///
/// # Errors
/// Returns [`HpkeError`] when randomness fails, the recipient public key is
/// malformed, HPKE encapsulation fails, or AEAD sealing fails.
pub fn wrap_dek(
    rng: &dyn SecureRandom,
    recipient_pubkey: &[u8; 32],
    dek_plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<WrapResult, HpkeError> {
    use hpke::single_shot_seal_in_place_detached;

    let pk_recip = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(recipient_pubkey)
        .map_err(|_| {
            HpkeError::InvalidInput("recipient_pubkey is not a 32-byte X25519 public key")
        })?;

    let mut buffer = dek_plaintext.to_vec();
    let mut csprng = SecureRandomRng::new(rng);
    let (encapped_key, tag) = single_shot_seal_in_place_detached::<
        HpkeChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(
        &hpke::OpModeS::Base,
        &pk_recip,
        info,
        &mut buffer,
        aad,
        &mut csprng,
    )?;
    if let Some(error) = csprng.take_error() {
        return Err(HpkeError::Random(error));
    }

    let mut ephemeral_pubkey = [0u8; 32];
    ephemeral_pubkey.copy_from_slice(&encapped_key.to_bytes());
    let mut aead_tag = [0u8; POLY1305_TAG_LEN];
    aead_tag.copy_from_slice(&tag.to_bytes());

    Ok(WrapResult {
        ephemeral_pubkey,
        ciphertext: buffer,
        aead_tag,
    })
}

/// Fixture-only seal — uses a pinned X25519 scalar as the ephemeral
/// private key. Production paths MUST NOT call this; Core §9.4 carve-out
/// language: "no production `Fact Producer`, `Canonical Append Service`,
/// or `Verifier` may rely on the pinned-key behavior."
///
/// **Gated behind the `test-vectors` Cargo feature.** A production build
/// of any crate downstream of `trellis-hpke` (i.e. without
/// `--features test-vectors` enabled) cannot link this symbol. The test
/// suite enables the feature explicitly via
/// `cargo nextest run -p trellis-hpke --features test-vectors`.
///
/// Implements RFC 9180 §5.1.1 Encap + §5.1 KeySchedule + AEAD seal
/// directly because `hpke::setup_sender` always runs DeriveKeyPair on
/// fresh randomness; raw-scalar pinning is the very flexibility
/// `setup_sender` is designed to forbid in production. The fixture
/// corpus's `gen_append_004.py` does the same dance — this is its Rust
/// twin.
///
/// # Errors
/// Returns [`HpkeError`] when KDF expansion or AEAD sealing fails.
#[cfg(feature = "test-vectors")]
pub fn wrap_dek_with_pinned_ephemeral(
    recipient_pubkey: &[u8; 32],
    ephemeral_privkey: &[u8; 32],
    dek_plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<WrapResult, HpkeError> {
    // 1. X25519 ephemeral keypair from the pinned scalar (carve-out).
    let sk_eph = X25519Static::from(*ephemeral_privkey);
    let pk_eph = X25519Public::from(&sk_eph);
    let ephemeral_pubkey: [u8; 32] = *pk_eph.as_bytes();

    // 2. RFC 9180 §4.1 DH(sk_eph, pk_recip).
    let pk_recip = X25519Public::from(*recipient_pubkey);
    let dh = sk_eph.diffie_hellman(&pk_recip);

    // 3. KEM.ExtractAndExpand(dh, kem_context = enc || pk_recip).
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(&ephemeral_pubkey);
    kem_context[32..].copy_from_slice(recipient_pubkey);
    let mut shared_secret = [0u8; 32];
    extract_and_expand::<HkdfSha256>(
        dh.as_bytes(),
        &KEM_SUITE_ID,
        &kem_context,
        &mut shared_secret,
    )
    .map_err(|_| HpkeError::Kdf("KEM extract_and_expand"))?;

    // 4. RFC 9180 §5.1 KeySchedule for mode_base (mode = 0x00).
    let (key, base_nonce) = derive_base_key_and_nonce(&shared_secret, info)?;

    // 5. AEAD seal with sequence number 0 (single-shot wrap).
    let aead = ChaCha20Poly1305::new(AeadGenericArray::from_slice(&key));
    let mut buffer = dek_plaintext.to_vec();
    let nonce_arr = AeadGenericArray::from_slice(&base_nonce);
    let tag = aead
        .encrypt_in_place_detached(nonce_arr, aad, &mut buffer)
        .map_err(|_| HpkeError::AeadFailure)?;
    let mut aead_tag = [0u8; POLY1305_TAG_LEN];
    aead_tag.copy_from_slice(tag.as_slice());

    Ok(WrapResult {
        ephemeral_pubkey,
        ciphertext: buffer,
        aead_tag,
    })
}

/// Production / verifier open — uses the recipient's 32-byte X25519
/// scalar to derive the receiver context and decrypt the wrap.
///
/// # Errors
/// Returns [`HpkeError`] when the recipient seed or ephemeral public key
/// is malformed, or AEAD authentication fails.
pub fn unwrap_dek(
    recipient_privkey: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    wrapped_dek: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    if wrapped_dek.len() < POLY1305_TAG_LEN {
        return Err(HpkeError::InvalidInput("wrapped_dek shorter than 16 bytes"));
    }

    let sk_recip = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(recipient_privkey)
        .map_err(|_| HpkeError::InvalidInput("recipient_privkey is not a 32-byte X25519 scalar"))?;
    let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(ephemeral_pubkey)
        .map_err(|_| {
        HpkeError::InvalidInput("ephemeral_pubkey is not a 32-byte X25519 public key")
    })?;

    let mut receiver_ctx = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk_recip,
        &encapped_key,
        info,
    )?;

    // `AeadCtxR::open` handles the ciphertext||tag split internally and
    // verifies the tag — the same wire shape Trellis stores in
    // `KeyBagEntry.wrapped_dek`.
    let plaintext = receiver_ctx.open(wrapped_dek, aad)?;
    Ok(plaintext)
}

/// RFC 9180 §5.1 KeySchedule for mode_base, suite 1 — derives `(key,
/// base_nonce)` from `shared_secret` and `info`. Empty PSK + empty PSK ID
/// per Base mode, empty info per Phase-1 §9.4 (but parameterized in case
/// a future suite registers a non-empty info).
#[cfg(feature = "test-vectors")]
fn derive_base_key_and_nonce(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], [u8; 12]), HpkeError> {
    // RFC 9180 §5.1: psk_id_hash, info_hash with mode-bound suite_id.
    let (psk_id_hash, _) = labeled_extract::<HkdfSha256>(&[], &HPKE_SUITE_ID, b"psk_id_hash", &[]);
    let (info_hash, _) = labeled_extract::<HkdfSha256>(&[], &HPKE_SUITE_ID, b"info_hash", info);

    // key_schedule_context = mode || psk_id_hash || info_hash.
    let mut key_schedule_context = [0u8; 1 + 32 + 32];
    key_schedule_context[0] = 0x00; // mode_base
    key_schedule_context[1..33].copy_from_slice(&psk_id_hash);
    key_schedule_context[33..].copy_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", "")
    let (_, secret_ctx) =
        labeled_extract::<HkdfSha256>(shared_secret, &HPKE_SUITE_ID, b"secret", &[]);

    // key, base_nonce derived from secret_ctx with key_schedule_context as info.
    let mut key = [0u8; 32];
    secret_ctx
        .labeled_expand(&HPKE_SUITE_ID, b"key", &key_schedule_context, &mut key)
        .map_err(|_| HpkeError::Kdf("labeled_expand key"))?;
    let mut base_nonce = [0u8; 12];
    secret_ctx
        .labeled_expand(
            &HPKE_SUITE_ID,
            b"base_nonce",
            &key_schedule_context,
            &mut base_nonce,
        )
        .map_err(|_| HpkeError::Kdf("labeled_expand base_nonce"))?;
    Ok((key, base_nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: production seal + verifier open returns the same DEK.
    /// Smoke test only — `tests/append_004_byte_match.rs` is the
    /// byte-exact oracle.
    #[test]
    fn wrap_then_unwrap_round_trip() {
        // Derive the recipient pubkey via the hpke crate's own KEM helper
        // so this test does not need `x25519-dalek` directly (which is
        // gated behind `test-vectors`).
        use hpke::{Kem, kem::X25519HkdfSha256};
        use integrity_seam::OsSecureRandom;
        let recipient_seed = [0x42u8; 32];
        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&recipient_seed)
            .expect("recipient sk");
        let pk = <X25519HkdfSha256 as Kem>::sk_to_pk(&sk);
        let mut recipient_pub = [0u8; 32];
        recipient_pub.copy_from_slice(&pk.to_bytes());

        let dek = b"some-32-byte-dek--padding-pad-pad";
        let rng = OsSecureRandom;
        let wrap =
            wrap_dek(&rng, &recipient_pub, dek, HPKE_SUITE1_INFO, HPKE_SUITE1_AAD).expect("wrap");

        let mut wire = wrap.ciphertext.clone();
        wire.extend_from_slice(&wrap.aead_tag);
        let plaintext = unwrap_dek(
            &recipient_seed,
            &wrap.ephemeral_pubkey,
            &wire,
            HPKE_SUITE1_INFO,
            HPKE_SUITE1_AAD,
        )
        .expect("unwrap");
        assert_eq!(plaintext, dek);
    }

    /// `wrap_dek_with_pinned_ephemeral` then `unwrap_dek` round-trips,
    /// independently of the `append/004` fixture. Gated under
    /// `test-vectors` like the function it exercises.
    #[cfg(feature = "test-vectors")]
    #[test]
    fn pinned_ephemeral_wrap_round_trips() {
        let recipient_seed = [0x55u8; 32];
        let recipient_pub = X25519Public::from(&X25519Static::from(recipient_seed));
        let ephemeral_seed = [0x77u8; 32];
        let dek = [0xabu8; 32];
        let wrap = wrap_dek_with_pinned_ephemeral(
            recipient_pub.as_bytes(),
            &ephemeral_seed,
            &dek,
            HPKE_SUITE1_INFO,
            HPKE_SUITE1_AAD,
        )
        .expect("wrap pinned");
        let mut wire = wrap.ciphertext.clone();
        wire.extend_from_slice(&wrap.aead_tag);
        let plaintext = unwrap_dek(
            &recipient_seed,
            &wrap.ephemeral_pubkey,
            &wire,
            HPKE_SUITE1_INFO,
            HPKE_SUITE1_AAD,
        )
        .expect("unwrap");
        assert_eq!(plaintext.as_slice(), dek.as_slice());
    }
}
