use ciborium::Value;
use trellis_types::{
    AUTHOR_EVENT_DOMAIN, EVENT_DOMAIN, domain_separated_sha256, encode_bstr, encode_tstr,
    encode_uint,
};

use super::{MERKLE_INTERIOR_DOMAIN, MERKLE_LEAF_DOMAIN};

pub(crate) fn recompute_author_event_hash(canonical_event_bytes: &[u8]) -> Option<[u8; 32]> {
    let authored = authored_preimage_from_canonical(canonical_event_bytes)?;
    Some(domain_separated_sha256(AUTHOR_EVENT_DOMAIN, &authored))
}

/// Recovers authored-event CBOR by stripping the `author_event_hash` entry
/// from the canonical map.
///
/// **Coupling:** The `canonical_event_from_authored` helper in `trellis-cddl`
/// always appends `author_event_hash` as the **last** map field with canonical
/// key encoding. If the CDDL map gains trailing fields or reorders keys, this
/// locator must be updated alongside that helper.
pub(crate) fn authored_preimage_from_canonical(canonical_event_bytes: &[u8]) -> Option<Vec<u8>> {
    let key = encode_tstr("author_event_hash");
    let key_position = canonical_event_bytes
        .windows(key.len())
        .rposition(|window| window == key.as_slice())?;
    let value_position = key_position + key.len();
    if canonical_event_bytes.len() != value_position + 34 {
        return None;
    }
    if canonical_event_bytes[value_position] != 0x58
        || canonical_event_bytes[value_position + 1] != 0x20
    {
        return None;
    }
    let mut authored = Vec::with_capacity(canonical_event_bytes.len() - 35);
    let new_map_prefix = canonical_event_bytes.first()?.checked_sub(1)?;
    authored.push(new_map_prefix);
    authored.extend_from_slice(&canonical_event_bytes[1..key_position]);
    Some(authored)
}

pub(crate) fn recompute_canonical_event_hash(
    scope: &[u8],
    canonical_event_bytes: &[u8],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("ledger_scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("event_payload"));
    preimage.extend_from_slice(canonical_event_bytes);
    domain_separated_sha256(EVENT_DOMAIN, &preimage)
}

pub(crate) fn merkle_leaf_hash(canonical_hash: [u8; 32]) -> [u8; 32] {
    domain_separated_sha256(MERKLE_LEAF_DOMAIN, &canonical_hash)
}

pub(crate) fn merkle_interior_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut joined = Vec::with_capacity(64);
    joined.extend_from_slice(&left);
    joined.extend_from_slice(&right);
    domain_separated_sha256(MERKLE_INTERIOR_DOMAIN, &joined)
}

pub(crate) fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        // Unreachable for valid checkpoints (`tree_size == 0` is rejected
        // earlier); kept as a defensive sentinel.
        0 => [0u8; 32],
        1 => leaves[0],
        _ => {
            let mut level = leaves.to_vec();
            while level.len() > 1 {
                let mut next = Vec::new();
                let mut index = 0;
                while index < level.len() {
                    if index + 1 == level.len() {
                        // RFC 6962 §2.1: unpaired end leaf is promoted without hashing
                        // with a duplicate of itself.
                        next.push(level[index]);
                    } else {
                        next.push(merkle_interior_hash(level[index], level[index + 1]));
                    }
                    index += 2;
                }
                level = next;
            }
            level[0]
        }
    }
}

pub(crate) fn digest_path_from_values(nodes: &[Value]) -> Result<Vec<[u8; 32]>, ()> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        let bytes = node.as_bytes().ok_or(())?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| ())?;
        out.push(array);
    }
    Ok(out)
}

pub(crate) fn inner_proof_size(index: u64, size: u64) -> usize {
    let xor = index ^ (size - 1);
    if xor == 0 {
        0
    } else {
        (u64::BITS - xor.leading_zeros()) as usize
    }
}

pub(crate) fn decomp_inclusion_proof(index: u64, size: u64) -> (usize, usize) {
    let inner = inner_proof_size(index, size);
    let border = (index >> inner).count_ones() as usize;
    (inner, border)
}

pub(crate) fn chain_inner_merkle(mut seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
    for (i, sibling) in proof.iter().enumerate() {
        if (index >> i) & 1 == 0 {
            seed = merkle_interior_hash(seed, *sibling);
        } else {
            seed = merkle_interior_hash(*sibling, seed);
        }
    }
    seed
}

pub(crate) fn chain_inner_right_merkle(
    mut seed: [u8; 32],
    proof: &[[u8; 32]],
    index: u64,
) -> [u8; 32] {
    for (i, sibling) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            seed = merkle_interior_hash(*sibling, seed);
        }
    }
    seed
}

pub(crate) fn chain_border_right_merkle(mut seed: [u8; 32], proof: &[[u8; 32]]) -> [u8; 32] {
    for sibling in proof {
        seed = merkle_interior_hash(*sibling, seed);
    }
    seed
}

pub(crate) fn root_from_inclusion_proof(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: [u8; 32],
    proof: &[[u8; 32]],
) -> Result<[u8; 32], ()> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Err(());
    }
    let (inner, border) = decomp_inclusion_proof(leaf_index, tree_size);
    if proof.len() != inner + border {
        return Err(());
    }
    let mut node = chain_inner_merkle(leaf_hash, &proof[..inner], leaf_index);
    node = chain_border_right_merkle(node, &proof[inner..]);
    Ok(node)
}

pub(crate) fn root_from_consistency_proof(
    size1: u64,
    size2: u64,
    root1: [u8; 32],
    proof: &[[u8; 32]],
) -> Result<[u8; 32], ()> {
    if size2 < size1 {
        return Err(());
    }
    if size1 == size2 {
        if !proof.is_empty() {
            return Err(());
        }
        return Ok(root1);
    }
    if size1 == 0 {
        return Err(());
    }
    if proof.is_empty() {
        return Err(());
    }
    let (mut inner, border) = decomp_inclusion_proof(size1 - 1, size2);
    let shift = size1.trailing_zeros() as usize;
    if inner < shift {
        return Err(());
    }
    inner -= shift;
    let mut seed = proof[0];
    let mut start = 1usize;
    if size1 == 1u64 << shift {
        seed = root1;
        start = 0;
    }
    if proof.len() != start + inner + border {
        return Err(());
    }
    let suffix = &proof[start..];
    let mask = (size1 - 1) >> shift;
    let hash1 = chain_inner_right_merkle(seed, &suffix[..inner], mask);
    let hash1 = chain_border_right_merkle(hash1, &suffix[inner..]);
    if hash1 != root1 {
        return Err(());
    }
    let hash2 = chain_inner_merkle(seed, &suffix[..inner], mask);
    Ok(chain_border_right_merkle(hash2, &suffix[inner..]))
}
