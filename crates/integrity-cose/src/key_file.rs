// Rust guideline compliant 2026-02-21

//! The key-file adapter for [`PurposeSigner`] (ADR 0169 section 1.2, ADR 0164 section 1.3).
//!
//! One file per purpose, read from the secrets store. The file holds the current Ed25519 seed
//! as 32 raw bytes, optionally followed by the previous public key as 32 raw bytes, so a
//! rotation publishes the next key beside the current one. Any other length is refused.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use integrity_seam::{PublicKeyInfo, Purpose, PurposeKeys, PurposeSigner, SignError, Signed};

use crate::{SUITE_ID_PHASE_1, derive_kid, sign_ed25519};

const SEED_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;

struct PurposeKey {
    seed: [u8; SEED_BYTES],
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
    let seed: [u8; SEED_BYTES] = seed.try_into().map_err(|_| invalid("seed is malformed"))?;
    let current = info(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
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
        seed,
        current,
        previous,
    })
}

impl KeyFileSigner {
    /// Builds a signer from key-file contents, one entry per purpose.
    ///
    /// # Errors
    /// Fails on a malformed file, a duplicate purpose, or one public key shared by two purposes.
    pub fn from_key_bytes(
        entries: impl IntoIterator<Item = (Purpose, Vec<u8>)>,
    ) -> Result<Self, SignError> {
        let mut keys = BTreeMap::new();
        for (purpose, bytes) in entries {
            if keys.insert(purpose, parse(purpose, &bytes)?).is_some() {
                return Err(SignError::InvalidKey(format!("{purpose} key given twice")));
            }
        }
        let mut seen: Vec<(Purpose, [u8; PUBLIC_KEY_BYTES])> = Vec::new();
        for (purpose, key) in &keys {
            if let Some((other, _)) = seen
                .iter()
                .find(|(_, public)| *public == key.current.public_key)
            {
                return Err(SignError::InvalidKey(format!(
                    "{other} and {purpose} share one public key"
                )));
            }
            seen.push((*purpose, key.current.public_key));
        }
        Ok(Self { keys })
    }

    /// Reads each purpose's key file from the secrets store.
    ///
    /// # Errors
    /// Fails when a file is unreadable, or on any error of [`Self::from_key_bytes`].
    pub fn from_key_files(entries: &[(Purpose, &Path)]) -> Result<Self, SignError> {
        let mut read = Vec::with_capacity(entries.len());
        for (purpose, path) in entries {
            let bytes = std::fs::read(path)
                .map_err(|_| SignError::InvalidKey(format!("{purpose} key file is unreadable")))?;
            read.push((*purpose, bytes));
        }
        Self::from_key_bytes(read)
    }

    fn key(&self, purpose: Purpose) -> Result<&PurposeKey, SignError> {
        self.keys.get(&purpose).ok_or(SignError::NoKey(purpose))
    }
}

impl PurposeSigner for KeyFileSigner {
    fn sign(
        &self,
        _scope_key: &[u8; 32],
        purpose: Purpose,
        input: &[u8],
    ) -> Result<Signed, SignError> {
        let key = self.key(purpose)?;
        Ok(Signed {
            kid: key.current.kid.clone(),
            signature: sign_ed25519(key.seed, input),
        })
    }

    fn keys(&self, purpose: Purpose) -> Result<PurposeKeys, SignError> {
        let key = self.key(purpose)?;
        Ok(PurposeKeys {
            current: key.current.clone(),
            previous: key.previous.clone(),
        })
    }
}
