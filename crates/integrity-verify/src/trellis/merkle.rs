use ciborium::Value;
use trellis_types::{
    AUTHOR_EVENT_DOMAIN, EVENT_DOMAIN, domain_separated_sha256, encode_bstr, encode_tstr,
    encode_uint,
};

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

pub(crate) fn digest_path_from_values(nodes: &[Value]) -> Result<Vec<[u8; 32]>, ()> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        let bytes = node.as_bytes().ok_or(())?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| ())?;
        out.push(array);
    }
    Ok(out)
}
