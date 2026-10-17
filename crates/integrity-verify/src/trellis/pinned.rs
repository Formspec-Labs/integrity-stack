//! Pinned signing keys: the trust anchor an export's own registry is checked against.
//!
//! An export carries its own signing-key registry, so a verifier that trusts it trusts whoever
//! built the export. A relying party that pins the deployment's public key history asks one more
//! question of a verified export: does every key it cites resolve to a pinned key? The history is
//! the file Trellis is started with (`TRELLIS_SIGNING_KEY_HISTORY_PATH`): a JSON array of rows
//! with a hex `public_key`, oldest first. Other fields are the server's concern.

use std::collections::BTreeMap;

use integrity_cose::derive_kid;

use super::export::parse_export_zip;
use super::parse::{decode_value, parse_key_registry, parse_sign1_array, parse_sign1_bytes};
use super::{SUITE_ID_PHASE_1_I128, util::hex_decode};
use trellis_types::map_lookup_fixed_bytes;

/// The public keys a deployment has signed with, by `kid`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PinnedSigningKeys {
    keys: BTreeMap<Vec<u8>, [u8; 32]>,
}

/// Why an export was not accepted against the pinned keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinnedExportRefusal {
    /// The export or its registry could not be read.
    Malformed(String),
    /// A manifest, event or checkpoint cites a `kid` that no pinned key has.
    UnpinnedSigner,
    /// The export's registry gives a pinned `kid` a different public key.
    RegistryKeyDiffers,
    /// The export's head checkpoint is not the one asked for.
    HeadCheckpointDiffers,
}

impl PinnedSigningKeys {
    /// Pins these Ed25519 public keys.
    #[must_use]
    pub fn from_public_keys(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|key| {
                    let suite = u64::try_from(SUITE_ID_PHASE_1_I128).expect("suite id fits u64");
                    (derive_kid(suite, key).to_vec(), key)
                })
                .collect(),
        }
    }

    /// Reads the public keys of a signing-key history file.
    ///
    /// # Errors
    /// Refuses an empty history or a row without a 64-hex-digit `public_key`.
    pub fn from_history_json(bytes: &[u8]) -> Result<Self, String> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid key history: {error}"))?;
        if rows.is_empty() {
            return Err("key history is empty".to_owned());
        }
        let keys = rows
            .iter()
            .map(|row| {
                row.get("public_key")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|hex| hex_decode(hex).ok())
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(|| "key history public_key must be 64 hex digits".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_public_keys(keys))
    }
}

/// Checks that every key a verified export cites is a pinned key, and optionally that its head
/// checkpoint is `expected_head`.
///
/// This adds to full export verification; it does not replace it.
///
/// # Errors
/// See [`PinnedExportRefusal`].
pub fn check_pinned_signers(
    export_zip: &[u8],
    pinned: &PinnedSigningKeys,
    expected_head: Option<[u8; 32]>,
) -> Result<(), PinnedExportRefusal> {
    let malformed = |what: &str| PinnedExportRefusal::Malformed(what.to_owned());
    let archive = parse_export_zip(export_zip).map_err(|error| malformed(&error.to_string()))?;
    let member = |name: &str| {
        archive
            .members
            .get(name)
            .ok_or_else(|| PinnedExportRefusal::Malformed(format!("export is missing {name}")))
    };
    let (registry, _) = parse_key_registry(member("030-signing-key-registry.cbor")?)
        .map_err(|error| malformed(&error.to_string()))?;
    let manifest = parse_sign1_bytes(member("000-manifest.cbor")?)
        .map_err(|error| malformed(&error.to_string()))?;
    let mut kids = vec![manifest.kid.clone()];
    for member_name in ["010-events.cbor", "040-checkpoints.cbor"] {
        let rows = parse_sign1_array(member(member_name)?)
            .map_err(|error| malformed(&error.to_string()))?;
        kids.extend(rows.into_iter().map(|row| row.kid));
    }
    for kid in kids {
        let Some(pinned_key) = pinned.keys.get(&kid) else {
            return Err(PinnedExportRefusal::UnpinnedSigner);
        };
        if registry.get(&kid).map(|entry| entry.public_key) != Some(*pinned_key) {
            return Err(PinnedExportRefusal::RegistryKeyDiffers);
        }
    }
    if let Some(expected) = expected_head {
        if export_head_checkpoint_digest(export_zip)? != expected {
            return Err(PinnedExportRefusal::HeadCheckpointDiffers);
        }
    }
    Ok(())
}

/// The head checkpoint digest the export's manifest names.
///
/// # Errors
/// [`PinnedExportRefusal::Malformed`] when the export has no readable manifest head.
pub fn export_head_checkpoint_digest(export_zip: &[u8]) -> Result<[u8; 32], PinnedExportRefusal> {
    let malformed = |what: String| PinnedExportRefusal::Malformed(what);
    let archive = parse_export_zip(export_zip).map_err(|error| malformed(error.to_string()))?;
    let manifest_bytes = archive
        .members
        .get("000-manifest.cbor")
        .ok_or_else(|| malformed("export is missing 000-manifest.cbor".to_owned()))?;
    let manifest =
        parse_sign1_bytes(manifest_bytes).map_err(|error| malformed(error.to_string()))?;
    let payload = manifest
        .payload
        .as_ref()
        .ok_or_else(|| malformed("manifest has no payload".to_owned()))?;
    let value = decode_value(payload).map_err(|error| malformed(error.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| malformed("manifest payload is not a map".to_owned()))?;
    map_lookup_fixed_bytes(map, "head_checkpoint_digest", 32)
        .map_err(|error| malformed(error.to_string()))?
        .try_into()
        .map_err(|_| malformed("head_checkpoint_digest is not 32 bytes".to_owned()))
}

#[cfg(test)]
mod tests;
