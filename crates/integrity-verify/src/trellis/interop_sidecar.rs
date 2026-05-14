use std::collections::BTreeSet;

use ciborium::Value;
use trellis_types::{
    CONTENT_DOMAIN, domain_separated_sha256, map_lookup_fixed_bytes, map_lookup_optional_value,
    map_lookup_text, map_lookup_u64,
};

use super::{
    INTEROP_SIDECAR_C2PA_MANIFEST_SUPPORTED_VERSIONS,
    INTEROP_SIDECAR_DID_KEY_VIEW_SUPPORTED_VERSIONS, INTEROP_SIDECAR_KIND_C2PA_MANIFEST,
    INTEROP_SIDECAR_KIND_DID_KEY_VIEW, INTEROP_SIDECAR_KIND_SCITT_RECEIPT,
    INTEROP_SIDECAR_KIND_VC_JOSE_COSE_EVENT, INTEROP_SIDECARS_PATH_PREFIX,
};
use crate::trellis::kinds::VerificationFailureKind;
use crate::trellis::types::{ExportArchive, InteropSidecarVerificationEntry, VerificationReport};

/// Path-prefix predicate (TR-CORE-167). The path is checked as raw
/// bytes — no normalization, no canonicalization, no Unicode folding.
/// Anything that does not start with the literal `interop-sidecars/`
/// byte sequence is invalid; this closes the path-traversal attack
/// surface where a manifest could redirect a `content_digest` check at
/// a canonical-tree file (e.g., `010-events.cbor`).
pub(crate) fn is_interop_sidecar_path_valid(path: &str) -> bool {
    path.starts_with(INTEROP_SIDECARS_PATH_PREFIX)
}

/// ADR 0008 §"Phase-1 verifier obligation" — dispatched verifier
/// (path-(b): digest-binds only). Walks
/// `manifest.interop_sidecars` and the on-disk `interop-sidecars/`
/// tree and produces one outcome per dispatched-kind entry. Fatal
/// short-circuits return a `VerificationReport::fatal` via the `Err`
/// arm; the caller propagates that report. Non-dispatched (locked-off)
/// kinds short-circuit with `interop_sidecar_phase_1_locked`.
///
/// Failure dispatch order (per ADR 0008 §"Phase-1 verifier obligation"
/// step 2): kind-registered → derivation-version-supported →
/// path-prefix-valid → phase-1-lock-off (`interop_sidecar_phase_1_locked`
/// for still-locked kinds) → content-digest-match. Files-on-disk
/// that are not manifest-listed → `interop_sidecar_unlisted_file` (after
/// manifest walk completes; closes the smuggled-sidecar attack surface).
/// For each manifest entry, checks run in this order; the verifier returns
/// the first failing check (one fatal `VerificationReport` per export, not
/// a bundle of competing failure codes).
#[allow(clippy::result_large_err)]
pub(crate) fn verify_interop_sidecars(
    manifest_map: &[(Value, Value)],
    archive: &ExportArchive,
) -> Result<Vec<InteropSidecarVerificationEntry>, VerificationReport> {
    let raw = match map_lookup_optional_value(manifest_map, "interop_sidecars") {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };
    if raw.is_null() {
        return Ok(Vec::new());
    }
    let entries = match raw.as_array() {
        Some(arr) => arr,
        None => {
            return Err(VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                "interop_sidecars must be an array or null",
            ));
        }
    };

    let mut outcomes: Vec<InteropSidecarVerificationEntry> = Vec::with_capacity(entries.len());
    let mut listed_paths: BTreeSet<String> = BTreeSet::new();

    for (index, entry) in entries.iter().enumerate() {
        let entry_map = match entry.as_map() {
            Some(map) => map,
            None => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("interop_sidecars[{index}] is not a map"),
                ));
            }
        };

        let kind = match map_lookup_text(entry_map, "kind") {
            Ok(kind) => kind,
            Err(error) => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("interop_sidecars[{index}].kind is invalid: {error}"),
                ));
            }
        };
        let path = match map_lookup_text(entry_map, "path") {
            Ok(path) => path,
            Err(error) => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("interop_sidecars[{index}].path is invalid: {error}"),
                ));
            }
        };
        let derivation_version = match map_lookup_u64(entry_map, "derivation_version") {
            Ok(value) if value <= u8::MAX as u64 => value as u8,
            Ok(value) => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!(
                        "interop_sidecars[{index}].derivation_version {value} exceeds uint .size 1"
                    ),
                ));
            }
            Err(error) => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("interop_sidecars[{index}].derivation_version is invalid: {error}"),
                ));
            }
        };
        let content_digest = match map_lookup_fixed_bytes(entry_map, "content_digest", 32) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("interop_sidecars[{index}].content_digest is invalid: {error}"),
                ));
            }
        };
        // ADR 0008 Open Q5 (resolved Wave 25): `source_ref` validated
        // for presence only; full resolution semantics deferred to a
        // future ADR. Decode-failure is a manifest-payload error;
        // empty / non-string is rejected at the CDDL boundary.
        match map_lookup_text(entry_map, "source_ref") {
            Ok(_) => {}
            Err(error) => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("interop_sidecars[{index}].source_ref is invalid: {error}"),
                ));
            }
        }

        // Step 2.a (kind-registered) — TR-CORE-164.
        let kind_registered = matches!(
            kind.as_str(),
            INTEROP_SIDECAR_KIND_C2PA_MANIFEST
                | INTEROP_SIDECAR_KIND_DID_KEY_VIEW
                | INTEROP_SIDECAR_KIND_SCITT_RECEIPT
                | INTEROP_SIDECAR_KIND_VC_JOSE_COSE_EVENT
        );
        if !kind_registered {
            return Err(VerificationReport::fatal(
                VerificationFailureKind::InteropSidecarKindUnknown,
                format!("interop_sidecars[{index}].kind {kind:?} is not in the ADR 0008 registry"),
            ));
        }

        // Step 2.b (derivation-version-supported) — TR-CORE-166. An
        // empty supported-version set means the registered kind remains
        // locked off and skips version rejection until Step 2.d.
        let supported_versions: &[u8] = match kind.as_str() {
            INTEROP_SIDECAR_KIND_C2PA_MANIFEST => INTEROP_SIDECAR_C2PA_MANIFEST_SUPPORTED_VERSIONS,
            INTEROP_SIDECAR_KIND_DID_KEY_VIEW => INTEROP_SIDECAR_DID_KEY_VIEW_SUPPORTED_VERSIONS,
            _ => &[],
        };
        if !supported_versions.is_empty() && !supported_versions.contains(&derivation_version) {
            return Err(VerificationReport::fatal(
                VerificationFailureKind::InteropSidecarDerivationVersionUnknown,
                format!(
                    "interop_sidecars[{index}] kind={kind:?} derivation_version={derivation_version} not in supported set"
                ),
            ));
        }

        // Step 2.c (path-prefix-valid) — TR-CORE-167. Predicate also covered
        // by `interop_sidecar_path_prefix_invariant`; full dispatch path by
        // `verify_interop_sidecars_rejects_manifest_path_outside_interop_tree`.
        if !is_interop_sidecar_path_valid(&path) {
            return Err(VerificationReport::fatal(
                VerificationFailureKind::InteropSidecarPathInvalid,
                format!(
                    "interop_sidecars[{index}].path {path:?} does not start with {INTEROP_SIDECARS_PATH_PREFIX:?}"
                ),
            ));
        }

        // Step 2.d (Phase-1 lock-off — locked kinds short-circuit here
        // AFTER passing structural checks, so a fixture mis-listing
        // kind+path under a still-locked kind surfaces the dominant
        // `interop_sidecar_phase_1_locked` failure rather than a
        // structural one).
        let phase_1_locked = supported_versions.is_empty();
        if phase_1_locked {
            return Err(VerificationReport::fatal(
                VerificationFailureKind::InteropSidecarPhase1Locked,
                format!(
                    "interop_sidecars[{index}] kind={kind:?} is still Phase-1 locked-off (ADR 0008 / ADR 0003)"
                ),
            ));
        }

        // Step 2.e (listed-file-present) — TR-CORE-168. The manifest
        // already promised bytes at this sidecar path; absence is a local
        // sidecar-catalog failure, not a digest mismatch.
        let actual_bytes = match archive.members.get(&path) {
            Some(bytes) => bytes,
            None => {
                return Err(VerificationReport::fatal(
                    VerificationFailureKind::InteropSidecarMissing,
                    format!(
                        "interop_sidecars[{index}].path {path:?} is missing from the export ZIP"
                    ),
                ));
            }
        };
        // Step 2.f (content-digest-match) — TR-CORE-163. Recompute
        // SHA-256 under domain tag `trellis-content-v1` over the on-disk
        // sidecar bytes.
        let actual_digest = domain_separated_sha256(CONTENT_DOMAIN, actual_bytes);
        let content_digest_ok = actual_digest.as_slice() == content_digest.as_slice();
        if !content_digest_ok {
            return Err(VerificationReport::fatal(
                VerificationFailureKind::InteropSidecarContentMismatch,
                format!(
                    "interop_sidecars[{index}].content_digest does not match SHA-256(trellis-content-v1, {path:?})"
                ),
            ));
        }

        listed_paths.insert(path.clone());
        outcomes.push(InteropSidecarVerificationEntry {
            kind,
            path,
            derivation_version,
            content_digest_ok: true,
            kind_registered: true,
            phase_1_locked: false,
            failures: Vec::new(),
        });
    }

    // Step 2.g (unlisted-file) — TR-CORE-165. Walk every archive
    // member under `interop-sidecars/` and assert it appears in
    // `listed_paths`. The check runs after the manifest walk so a
    // first manifest-listed entry with a digest-mismatch wins
    // localization over a stray file (auditors expect to see the
    // explicit listing failure, not a confusing "unlisted file"
    // signal whose root cause is digest divergence).
    for member_path in archive.members.keys() {
        if !member_path.starts_with(INTEROP_SIDECARS_PATH_PREFIX) {
            continue;
        }
        if listed_paths.contains(member_path) {
            continue;
        }
        return Err(VerificationReport::fatal(
            VerificationFailureKind::InteropSidecarUnlistedFile,
            format!(
                "{member_path:?} is present under interop-sidecars/ but not catalogued in manifest.interop_sidecars"
            ),
        ));
    }

    Ok(outcomes)
}
