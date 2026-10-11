// Rust guideline compliant 2026-02-21
//! Composes maintained AEAD and HPKE for an explicitly selected external attachment profile.
//!
//! This is not the interpretation of legacy external records. The owning author
//! must authenticate the profile marker, original digest/length and event
//! idempotency key before calling these functions. Source acceptance, recipient
//! authority, native event encoding and durable replay belong to that author.
//! Every protection call generates new keys: retain the complete successful
//! output before append and reuse it for retries, rather than protecting again.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use integrity_cbor::encode_bstr;
use integrity_seam::SecureRandom;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{HPKE_SUITE1_AAD, HPKE_SUITE1_INFO, HpkeError, unwrap_dek, wrap_dek};

/// Explicit opt-in profile; the owning native event must authenticate this selection.
pub const EXTERNAL_ATTACHMENT_PROFILE: &str = "trellis.external-attachment-suite1.v1";
// Existing Core §9.4 nonce derivation, explicitly selected for this new profile.
const NONCE_INFO: &[u8] = b"trellis-payload-nonce-v1";
const TAG_BYTES: usize = 16;
const DEK_BYTES: usize = 32;
const HPKE_SUITE: u64 = 1;

/// Original attachment facts and event identity supplied by the owning author.
#[derive(Clone, Copy)]
pub struct AttachmentContext<'a> {
    pub idempotency_key: &'a [u8],
    pub original_sha256: [u8; 32],
    pub original_byte_length: u64,
}

impl std::fmt::Debug for AttachmentContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentContext")
            .field("original_byte_length", &self.original_byte_length)
            .finish_non_exhaustive()
    }
}

/// Finite deployment-selected limits, checked before expensive work.
#[derive(Clone, Copy, Debug)]
pub struct ProtectionLimits {
    pub original_bytes: usize,
    pub recipients: usize,
    pub recipient_id_bytes: usize,
}

/// An externally authorized recipient and its X25519 public key.
#[derive(Clone, Copy)]
pub struct Recipient<'a> {
    pub id: &'a [u8],
    pub public_key: [u8; 32],
}

impl std::fmt::Debug for Recipient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recipient").finish_non_exhaustive()
    }
}

/// Actual suite-1 KeyBag row; no plaintext key material is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedPayloadKey {
    pub recipient: Vec<u8>,
    pub suite: u64,
    pub ephemeral_pubkey: [u8; 32],
    pub wrapped_dek: Vec<u8>,
}

/// Exact ciphertext and decoding metadata for the owning typed event author.
///
/// `ciphertext` is AEAD ciphertext followed by its 16-byte tag; it has no nonce
/// prefix. Trellis owns serialization of KeyBag and the authenticated profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedExternalAttachment {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_bag: Vec<WrappedPayloadKey>,
}

fn invalid(why: &'static str) -> HpkeError {
    HpkeError::InvalidInput(why)
}

fn validate(context: AttachmentContext<'_>, limits: ProtectionLimits) -> Result<usize, HpkeError> {
    if !(1..=64).contains(&context.idempotency_key.len()) {
        return Err(invalid("idempotency key must contain 1..64 bytes"));
    }
    if limits.original_bytes == 0 || limits.recipients == 0 || limits.recipient_id_bytes == 0 {
        return Err(invalid("protection limits must be nonzero"));
    }
    let length = usize::try_from(context.original_byte_length)
        .map_err(|_| invalid("original length does not fit platform"))?;
    if length > limits.original_bytes || length.checked_add(TAG_BYTES).is_none() {
        return Err(invalid("original exceeds protection limit"));
    }
    Ok(length)
}

/// Derives the selected profile's nonce from already authenticated event identity and raw digest.
///
/// The owning author/reader may use this to check decoding metadata without copying HKDF logic.
/// Original byte length does not participate in nonce derivation.
///
/// # Errors
/// Refuses an idempotency key outside the profile's 1..64-byte bound.
pub fn derive_external_attachment_nonce(
    context: AttachmentContext<'_>,
) -> Result<[u8; 12], HpkeError> {
    if !(1..=64).contains(&context.idempotency_key.len()) {
        return Err(invalid("idempotency key must contain 1..64 bytes"));
    }
    let salt = encode_bstr(context.idempotency_key);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &context.original_sha256);
    let mut nonce = [0; 12];
    hkdf.expand(NONCE_INFO, &mut nonce)
        .map_err(|_| HpkeError::Kdf("attachment nonce"))?;
    Ok(nonce)
}

fn matches_original(context: AttachmentContext<'_>, original: &[u8]) -> bool {
    original.len() as u64 == context.original_byte_length
        && <[u8; 32]>::from(Sha256::digest(original)) == context.original_sha256
}

/// Protects exact original bytes for the selected external attachment profile.
///
/// Randomness and authorized recipients are injected; no keys or authority are selected here.
///
/// # Errors
/// Refuses inconsistent originals, invalid limits/recipients, entropy failure or crypto failure.
pub fn protect_external_attachment(
    random: &dyn SecureRandom,
    context: AttachmentContext<'_>,
    original: &[u8],
    recipients: &[Recipient<'_>],
    limits: ProtectionLimits,
) -> Result<ProtectedExternalAttachment, HpkeError> {
    let length = validate(context, limits)?;
    if original.len() != length || !matches_original(context, original) {
        return Err(invalid("original bytes disagree with signed digest/length"));
    }
    if recipients.is_empty() || recipients.len() > limits.recipients {
        return Err(invalid("recipient count outside protection limit"));
    }
    for (i, recipient) in recipients.iter().enumerate() {
        if recipient.id.is_empty() || recipient.id.len() > limits.recipient_id_bytes {
            return Err(invalid("recipient identity outside protection limit"));
        }
        if recipients[..i].iter().any(|prior| prior.id == recipient.id) {
            return Err(invalid("duplicate recipient identity"));
        }
    }
    let nonce = derive_external_attachment_nonce(context)?;
    let mut dek = Zeroizing::new([0; DEK_BYTES]);
    random
        .fill_bytes(dek.as_mut())
        .map_err(|error| HpkeError::Random(error.to_string()))?;
    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_ref()).map_err(|_| invalid("DEK size"))?;
    let mut ciphertext = Zeroizing::new(original.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut ciphertext)
        .map_err(|_| HpkeError::AeadFailure)?;
    ciphertext.extend_from_slice(&tag);
    let mut key_bag: Vec<WrappedPayloadKey> = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let wrapped = wrap_dek(
            random,
            &recipient.public_key,
            dek.as_ref(),
            HPKE_SUITE1_INFO,
            HPKE_SUITE1_AAD,
        )?;
        if key_bag
            .iter()
            .any(|prior| prior.ephemeral_pubkey == wrapped.ephemeral_pubkey)
        {
            return Err(invalid("repeated HPKE ephemeral within payload"));
        }
        let mut wrapped_dek = wrapped.ciphertext;
        wrapped_dek.extend_from_slice(&wrapped.aead_tag);
        key_bag.push(WrappedPayloadKey {
            recipient: recipient.id.to_vec(),
            suite: HPKE_SUITE,
            ephemeral_pubkey: wrapped.ephemeral_pubkey,
            wrapped_dek,
        });
    }
    Ok(ProtectedExternalAttachment {
        ciphertext: std::mem::take(&mut *ciphertext),
        nonce,
        key_bag,
    })
}

/// Opens protected bytes and verifies the authenticated original digest and length.
///
/// The caller must first authenticate context, profile and recipient selection.
/// Returned originals remain sensitive and belong to the authorized owning reader.
///
/// # Errors
/// Refuses invalid bounds/metadata, wrong keys, modified wraps/body or mismatched originals.
pub fn open_external_attachment(
    context: AttachmentContext<'_>,
    ciphertext: &[u8],
    recipient: &WrappedPayloadKey,
    private_key: &[u8; 32],
    limits: ProtectionLimits,
) -> Result<Vec<u8>, HpkeError> {
    let length = validate(context, limits)?;
    if ciphertext.len() != length + TAG_BYTES
        || recipient.suite != HPKE_SUITE
        || recipient.recipient.is_empty()
        || recipient.recipient.len() > limits.recipient_id_bytes
        || recipient.wrapped_dek.len() != DEK_BYTES + TAG_BYTES
    {
        return Err(invalid("protected attachment metadata/body shape"));
    }
    let dek = Zeroizing::new(unwrap_dek(
        private_key,
        &recipient.ephemeral_pubkey,
        &recipient.wrapped_dek,
        HPKE_SUITE1_INFO,
        HPKE_SUITE1_AAD,
    )?);
    if dek.len() != DEK_BYTES {
        return Err(invalid("unwrapped DEK size"));
    }
    let nonce = derive_external_attachment_nonce(context)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&dek).map_err(|_| invalid("DEK size"))?;
    let mut original = Zeroizing::new(ciphertext.to_vec());
    let tag = original.split_off(length);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            b"",
            &mut original,
            chacha20poly1305::Tag::from_slice(&tag),
        )
        .map_err(|_| HpkeError::AeadFailure)?;
    if !matches_original(context, &original) {
        return Err(invalid(
            "opened original disagrees with signed digest/length",
        ));
    }
    Ok(std::mem::take(&mut *original))
}
