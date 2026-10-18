// Rust guideline compliant 2026-02-21

//! The key-file adapter for [`PurposeSigner`] (ADR 0169 section 1.2, ADR 0164 section 1.3).
//!
//! One file per purpose, read from the secrets store. The file holds the current Ed25519 seed
//! as 32 raw bytes, optionally followed by the previous public key as 32 raw bytes, so a
//! rotation publishes the next key beside the current one. Any other length is refused.
//!
//! This adapter takes file contents, not paths: the caller reads the file with an owner-only
//! check (`stack_common_private_file::read_private_file`), as WOS and Trellis do.

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use integrity_seam::{PublicKeyInfo, Purpose, PurposeKeys, PurposeSigner, SignError, Signed};
use zeroize::Zeroize;

use crate::{SUITE_ID_PHASE_1, derive_kid};

const SEED_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;

struct PurposeKey {
    /// Zeroized when dropped.
    key: SigningKey,
    current: PublicKeyInfo,
    previous: Option<PublicKeyInfo>,
}

/// Signs with one key-file key per purpose. Scope keys are accepted and ignored.
pub struct KeyFileSigner {
    keys: BTreeMap<Purpose, PurposeKey>,
}

impl fmt::Debug for KeyFileSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyFileSigner")
            .field("purposes", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn info(public_key: [u8; PUBLIC_KEY_BYTES]) -> PublicKeyInfo {
    PublicKeyInfo {
        kid: hex::encode(derive_kid(SUITE_ID_PHASE_1, public_key)),
        public_key,
    }
}

fn parse(purpose: Purpose, bytes: &[u8]) -> Result<PurposeKey, SignError> {
    let invalid = |reason: &str| SignError::InvalidKey(format!("{purpose} key file {reason}"));
    let (seed, previous) = match bytes.len() {
        SEED_BYTES => (bytes, None),
        n if n == SEED_BYTES + PUBLIC_KEY_BYTES => {
            let (seed, previous) = bytes.split_at(SEED_BYTES);
            (seed, Some(previous))
        }
        _ => return Err(invalid("must hold 32 or 64 raw bytes")),
    };
    let mut seed: [u8; SEED_BYTES] = seed.try_into().map_err(|_| invalid("seed is malformed"))?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let current = info(key.verifying_key().to_bytes());
    let previous = previous
        .map(|raw| {
            let raw: [u8; PUBLIC_KEY_BYTES] = raw
                .try_into()
                .map_err(|_| invalid("previous key is malformed"))?;
            VerifyingKey::from_bytes(&raw).map_err(|_| invalid("previous key is not a point"))?;
            if raw == current.public_key {
                return Err(invalid("previous key equals the current key"));
            }
            Ok(info(raw))
        })
        .transpose()?;
    Ok(PurposeKey {
        key,
        current,
        previous,
    })
}

impl KeyFileSigner {
    /// Builds a signer from key-file contents, one entry per purpose, and zeroizes the contents.
    ///
    /// # Errors
    /// Fails on a malformed file, a duplicate purpose, or one public key shared by two purposes.
    pub fn from_key_bytes(
        entries: impl IntoIterator<Item = (Purpose, Vec<u8>)>,
    ) -> Result<Self, SignError> {
        let mut keys = BTreeMap::new();
        for (purpose, mut bytes) in entries {
            let parsed = parse(purpose, &bytes);
            // The raw file contents held a seed: wipe them whether or not they parsed.
            bytes.zeroize();
            if keys.insert(purpose, parsed?).is_some() {
                return Err(SignError::InvalidKey(format!("{purpose} key given twice")));
            }
        }
        let mut seen: Vec<(Purpose, [u8; PUBLIC_KEY_BYTES])> = Vec::new();
        for (purpose, key) in &keys {
            for public in std::iter::once(&key.current).chain(key.previous.as_ref()) {
                if let Some((other, _)) = seen.iter().find(|(_, seen)| *seen == public.public_key) {
                    return Err(SignError::InvalidKey(format!(
                        "{other} and {purpose} share one public key"
                    )));
                }
                seen.push((*purpose, public.public_key));
            }
        }
        Ok(Self { keys })
    }

    /// Returns the public metadata for an already loaded purpose without doing I/O.
    ///
    /// # Errors
    /// Returns [`SignError::NoKey`] when the purpose has no configured key.
    pub fn public_keys(&self, purpose: Purpose) -> Result<PurposeKeys, SignError> {
        let key = self.key(purpose)?;
        Ok(PurposeKeys {
            current: key.current.clone(),
            previous: key.previous.clone(),
        })
    }

    fn key(&self, purpose: Purpose) -> Result<&PurposeKey, SignError> {
        self.keys.get(&purpose).ok_or(SignError::NoKey(purpose))
    }
}

#[async_trait]
impl PurposeSigner for KeyFileSigner {
    async fn sign(
        &self,
        _scope_key: &[u8; 32],
        purpose: Purpose,
        input: &[u8],
    ) -> Result<Signed, SignError> {
        let key = self.key(purpose)?;
        Ok(Signed {
            kid: key.current.kid.clone(),
            signature: key.key.sign(input).to_bytes(),
        })
    }

    async fn keys(&self, purpose: Purpose) -> Result<PurposeKeys, SignError> {
        self.public_keys(purpose)
    }
}
