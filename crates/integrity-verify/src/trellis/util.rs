use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use trellis_types::map_lookup_optional_value;

use super::{
    OPERATOR_URI_PREFIX_TRELLIS, OPERATOR_URI_PREFIX_WOS, PHASE_1_TEST_IDENTITY_EVENT_TYPE,
};
use crate::trellis::types::VerifyError;

/// Minimal RFC 3986 syntactic URI check used for ADR 0010 §"Verifier
/// obligations" step 2 `signing_intent` validation. Per the ADR, Trellis
/// owns the bytes and WOS owns the meaning — we verify syntactic validity
/// only (scheme present, well-formed). The check accepts:
///   - a non-empty `scheme` per RFC 3986 §3.1
///     (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`)
///   - followed by a `:` separator
///   - followed by any non-empty remainder (the Phase-1 reference verifier
///     does not validate the URI body shape; deployment-side lint
///     tightens this when intent registries ratify per PLN-0380).
///
/// Returns `false` for empty strings, missing `:`, empty schemes, schemes
/// starting with a non-ALPHA character, or schemes containing characters
/// outside the RFC 3986 `scheme` production. URIs without an authority
/// component (e.g. `urn:trellis:intent:notarial`) are admitted.
pub(crate) fn is_syntactically_valid_uri(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if scheme.is_empty() || rest.is_empty() {
        return false;
    }
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

/// Companion §6.4 operator-URI prefix check used for ADR 0010 §"Verifier
/// obligations" step 8 (`user_content_attestation_operator_in_user_slot`).
/// The Phase-1 verifier checks against the conservative
/// `urn:trellis:operator:` and `urn:wos:operator:` prefixes; deployments
/// substitute or extend this list via deployment-local lint per the ADR
/// 0010 §"Adversary model" "operator masquerading as user" mitigation.
pub(crate) fn is_operator_uri(value: &str) -> bool {
    value.starts_with(OPERATOR_URI_PREFIX_TRELLIS) || value.starts_with(OPERATOR_URI_PREFIX_WOS)
}

/// Phase-1 identity-attestation event-type admission.
///
/// Admits the `x-trellis-test/*` reserved fixture identifier (Core §6.7 +
/// §10.6). Consumer-owned identity taxonomies are admitted through the
/// `RecordValidator` seam.
pub(crate) fn is_identity_attestation_event_type(event_type: &str) -> bool {
    event_type == PHASE_1_TEST_IDENTITY_EVENT_TYPE
}

/// ADR 0005 step 3 — validates the cross-field shape of `subject_scope`
/// based on `kind`.
pub(crate) fn validate_subject_scope_shape(
    subject_scope_map: &[(Value, Value)],
    kind: &str,
) -> Result<(), VerifyError> {
    let subject_refs = map_lookup_optional_value(subject_scope_map, "subject_refs");
    let ledger_scopes = map_lookup_optional_value(subject_scope_map, "ledger_scopes");
    let tenant_refs = map_lookup_optional_value(subject_scope_map, "tenant_refs");

    let is_present = |value: Option<&Value>| -> bool {
        matches!(value, Some(Value::Array(array)) if !array.is_empty())
    };
    let is_null_or_absent = |value: Option<&Value>| -> bool {
        matches!(value, None | Some(Value::Null))
            || matches!(value, Some(Value::Array(array)) if array.is_empty())
    };

    let ok = match kind {
        "per-subject" => {
            is_present(subject_refs)
                && is_null_or_absent(ledger_scopes)
                && is_null_or_absent(tenant_refs)
        }
        "per-scope" => {
            is_null_or_absent(subject_refs)
                && is_present(ledger_scopes)
                && is_null_or_absent(tenant_refs)
        }
        "per-tenant" => {
            is_null_or_absent(subject_refs)
                && is_null_or_absent(ledger_scopes)
                && is_present(tenant_refs)
        }
        "deployment-wide" => {
            is_null_or_absent(subject_refs)
                && is_null_or_absent(ledger_scopes)
                && is_null_or_absent(tenant_refs)
        }
        _ => {
            return Err(VerifyError::new(format!(
                "erasure-evidence subject_scope.kind `{kind}` is not one of per-subject / per-scope / per-tenant / deployment-wide (ADR 0005 step 3)"
            )));
        }
    };
    if !ok {
        return Err(VerifyError::new(format!(
            "erasure-evidence subject_scope cross-field shape violates ADR 0005 step 3 for kind `{kind}`"
        )));
    }
    Ok(())
}

pub(crate) fn binding_lineage_graph_has_cycle(adj: &BTreeMap<[u8; 32], Vec<[u8; 32]>>) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Color {
        White,
        Gray,
        Black,
    }

    let mut nodes: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (from, tos) in adj {
        nodes.insert(*from);
        for t in tos {
            nodes.insert(*t);
        }
    }

    let mut color: BTreeMap<[u8; 32], Color> = BTreeMap::new();
    for node in &nodes {
        color.insert(*node, Color::White);
    }

    fn dfs(
        node: [u8; 32],
        adj: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
        color: &mut BTreeMap<[u8; 32], Color>,
    ) -> bool {
        use Color::{Black, Gray, White};
        match color.get(&node).copied().unwrap_or(White) {
            Gray => return true,
            Black => return false,
            White => {}
        }
        color.insert(node, Gray);
        if let Some(neighbors) = adj.get(&node) {
            for &next in neighbors {
                if dfs(next, adj, color) {
                    return true;
                }
            }
        }
        color.insert(node, Black);
        false
    }

    for node in nodes {
        if matches!(color.get(&node).copied(), Some(Color::White)) && dfs(node, adj, &mut color) {
            return true;
        }
    }
    false
}

pub(crate) fn requires_dual_attestation(from_state: &str, to_state: &str) -> bool {
    custody_rank(to_state) > custody_rank(from_state)
}

pub(crate) fn custody_rank(value: &str) -> i32 {
    match value {
        "CM-A" => 3,
        "CM-B" => 2,
        "CM-C" => 1,
        _ => 0,
    }
}

pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn hex_decode(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.len() % 2 != 0 {
        return Err(VerifyError::new("hex string must have even length"));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

pub(crate) fn hex_nibble(value: u8) -> Result<u8, VerifyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(VerifyError::new("hex string contains a non-hex digit")),
    }
}

pub(crate) fn parse_sha256_text(value: &str) -> Result<[u8; 32], VerifyError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(VerifyError::new("hash text must use sha256: prefix"));
    };
    let bytes = hex_decode(hex)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::new("sha256 hash text must be 32 bytes"))
}

pub(crate) fn bytes_array(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("caller validates fixed size")
}
