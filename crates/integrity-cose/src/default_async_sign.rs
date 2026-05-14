// Rust guideline compliant 2026-02-21

//! Default async COSE signing helper.
//!
//! The helper lives in `integrity-cose` so Ed25519 and base64 dependencies stay
//! next to the COSE_Sign1 implementation instead of leaking into
//! `integrity-seam`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use integrity_seam::{SealError, SealInput, SealedEnvelope};

/// Signs a seal input as an embedded-payload COSE_Sign1 envelope.
///
/// # Errors
/// Returns an error when the seal input carries a malformed key identifier.
pub async fn default_async_sign(
    input: &SealInput,
    signing_key: &SigningKey,
) -> Result<SealedEnvelope, SealError> {
    let kid = decode_hex_kid(&input.kid)?;
    let protected = crate::protected_header_bytes(kid);
    let sig_structure = crate::sig_structure_bytes(&protected, &input.domain_separated_bytes);
    let signature = crate::sign_ed25519(signing_key.to_bytes(), &sig_structure);
    let sign1 = crate::sign1_bytes(&protected, &input.domain_separated_bytes, signature);

    Ok(SealedEnvelope {
        domain: input.domain.clone(),
        kid: input.kid.clone(),
        cose_sign1_b64: STANDARD.encode(sign1),
        canonical_event_hash: input.canonical_event_hash.clone(),
    })
}

fn decode_hex_kid(kid: &str) -> Result<[u8; 16], SealError> {
    let bytes = hex::decode(kid).map_err(|error| SealError::Sign(format!("kid hex: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        SealError::Sign(format!("kid must be 16 bytes, got {}", bytes.len()))
    })
}
