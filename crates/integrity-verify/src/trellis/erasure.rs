use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use trellis_types::sha256_bytes;

use super::ERASURE_EVIDENCE_EVENT_EXTENSION;
use crate::trellis::kinds::VerificationFailureKind;
use crate::trellis::parse::{decode_event_details, parse_erasure_catalog_entries};
use crate::trellis::types::*;
use crate::trellis::util::hex_string;

/// ADR 0005 §"Verifier obligations" finalization pass: runs steps 2 / 5 / 7
/// / 8 / 10 after every event has been individually decoded. Steps 1, 3, 4,
/// and 6 ran inline in [`decode_erasure_evidence_details`] (those checks
/// are local to one event and short-circuit on first violation). Step 9
/// (cascade-scope cross-check) is reserved for a Phase-2 deep-cascade pass.
///
/// Localizable failures are pushed into `event_failures` so the report's
/// `tamper_kind` projection picks them up; cross-payload group failures
/// (`erasure_destroyed_at_conflict`, `erasure_key_class_payload_conflict`)
/// localize to the second-emitted payload's canonical hash so the auditor
/// can find the disagreement by walking forward from the first row.
pub(crate) fn finalize_erasure_evidence(
    payloads: &[(usize, ErasureEvidenceDetails, [u8; 32])],
    chain: &[ChainEventSummary],
    registry: &BTreeMap<Vec<u8>, SigningKeyEntry>,
    non_signing_registry: Option<&BTreeMap<Vec<u8>, NonSigningKeyEntry>>,
    event_failures: &mut Vec<VerificationFailure>,
) -> Vec<ErasureEvidenceOutcome> {
    if payloads.is_empty() {
        return Vec::new();
    }

    // Step 5 / 8 group state — keyed by `kid_destroyed` bytes.
    let mut group_destroyed_at: BTreeMap<Vec<u8>, TrellisTimestamp> = BTreeMap::new();
    let mut group_key_class: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    let mut group_conflict_destroyed_at: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut group_conflict_key_class: BTreeSet<Vec<u8>> = BTreeSet::new();

    let mut outcomes: Vec<ErasureEvidenceOutcome> = Vec::with_capacity(payloads.len());

    // First pass: step 2 (registry bind) per payload + step 5 (group
    // destroyed_at / key_class agreement). Localize conflicts on the
    // second-encountered row.
    for (index, payload, canonical_hash) in payloads {
        // Step 2: registry bind. If `kid_destroyed` resolves to exactly one
        // KeyEntry row, `norm_key_class` MUST match that row's `kind`. For
        // legacy flat `SigningKeyEntry` (no `kind` on the row), the
        // expected class is `signing`.
        let registry_class: Option<&str> = if registry.contains_key(&payload.kid_destroyed) {
            Some("signing")
        } else if let Some(non_signing) = non_signing_registry
            && let Some(entry) = non_signing.get(&payload.kid_destroyed)
        {
            Some(entry.class.as_str())
        } else {
            None
        };

        if let Some(expected_class) = registry_class
            && expected_class != payload.norm_key_class
        {
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureKeyClassRegistryMismatch,
                hex_string(canonical_hash),
            ));
        }

        // Step 5: group by kid_destroyed. First payload sets the canonical
        // destroyed_at + key_class; subsequent rows must agree byte-for-byte.
        match group_destroyed_at.entry(payload.kid_destroyed.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(payload.destroyed_at);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if *entry.get() != payload.destroyed_at
                    && !group_conflict_destroyed_at.contains(&payload.kid_destroyed)
                {
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ErasureDestroyedAtConflict,
                        hex_string(canonical_hash),
                    ));
                    group_conflict_destroyed_at.insert(payload.kid_destroyed.clone());
                }
            }
        }
        match group_key_class.entry(payload.kid_destroyed.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(payload.norm_key_class.clone());
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if entry.get() != &payload.norm_key_class
                    && !group_conflict_key_class.contains(&payload.kid_destroyed)
                {
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ErasureKeyClassPayloadConflict,
                        hex_string(canonical_hash),
                    ));
                    group_conflict_key_class.insert(payload.kid_destroyed.clone());
                }
            }
        }

        outcomes.push(ErasureEvidenceOutcome {
            evidence_id: payload.evidence_id.clone(),
            kid_destroyed: payload.kid_destroyed.clone(),
            destroyed_at: payload.destroyed_at,
            cascade_scopes: payload.cascade_scopes.clone(),
            completion_mode: payload.completion_mode.clone(),
            event_index: *index as u64,
            signature_verified: payload.attestation_signatures_well_formed,
            post_erasure_uses: 0,
            post_erasure_wraps: 0,
            cascade_violations: Vec::new(),
            failures: Vec::new(),
        });
    }

    // Step 8: chain consistency for `norm_key_class ∈ {"signing", "subject"}`.
    // For each kid_destroyed group with a non-conflicting destroyed_at +
    // key_class, walk every chain event with `authored_at > destroyed_at`
    // and flag uses / wraps.
    for outcome in outcomes.iter_mut() {
        // Skip groups that already failed step 5 — propagating step-8 noise
        // on top of a destroyed_at conflict is misleading.
        if group_conflict_destroyed_at.contains(&outcome.kid_destroyed) {
            outcome
                .failures
                .push("erasure_destroyed_at_conflict".into());
            continue;
        }
        if group_conflict_key_class.contains(&outcome.kid_destroyed) {
            outcome
                .failures
                .push("erasure_key_class_payload_conflict".into());
            continue;
        }
        let class = group_key_class
            .get(&outcome.kid_destroyed)
            .map(String::as_str)
            .unwrap_or("");
        if class != "signing" && class != "subject" {
            // ADR 0005 step 8 Phase-1 scope: only signing + subject classes
            // run the chain walk. recovery / scope / tenant-root and
            // extension `tstr` classes are admitted at the wire layer; the
            // subtree obligations co-land with ADR 0006 follow-on milestones.
            continue;
        }
        let destroyed_at = match group_destroyed_at.get(&outcome.kid_destroyed) {
            Some(value) => *value,
            None => continue,
        };
        for event in chain {
            if event.authored_at <= destroyed_at {
                continue;
            }
            if event.signing_kid == outcome.kid_destroyed {
                outcome.post_erasure_uses += 1;
                outcome.failures.push("post_erasure_use".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::PostErasureUse,
                    hex_string(&event.canonical_event_hash),
                ));
            }
            if event
                .wrap_recipients
                .iter()
                .any(|recipient| recipient == &outcome.kid_destroyed)
            {
                outcome.post_erasure_wraps += 1;
                outcome.failures.push("post_erasure_wrap".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::PostErasureWrap,
                    hex_string(&event.canonical_event_hash),
                ));
            }
        }
    }

    // Step 7 (Phase-1 structural): `signature_verified = false` already set
    // on individual outcomes if any attestation row is malformed; surface a
    // localized failure so `integrity_verified` flips and the
    // `tamper_kind` projection can find it.
    for outcome in outcomes.iter() {
        if !outcome.signature_verified {
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureAttestationSignatureInvalid,
                hex_string(&[0u8; 32]),
            ));
        }
    }

    outcomes
}

pub(crate) fn erasure_catalog_row_matches_details(
    row: &ErasureEvidenceCatalogEntryRow,
    details: &EventDetails,
) -> bool {
    let Some(erasure) = details.erasure() else {
        return false;
    };
    if row.canonical_event_hash != details.canonical_event_hash {
        return false;
    }
    if row.evidence_id != erasure.evidence_id {
        return false;
    }
    if row.kid_destroyed.as_slice() != erasure.kid_destroyed.as_slice() {
        return false;
    }
    if row.destroyed_at != erasure.destroyed_at {
        return false;
    }
    if row.completion_mode != erasure.completion_mode {
        return false;
    }
    if row.cascade_scopes != erasure.cascade_scopes {
        return false;
    }
    if row.subject_scope_kind != erasure.subject_scope_kind {
        return false;
    }
    true
}

pub(crate) fn verify_erasure_evidence_catalog(
    archive: &ExportArchive,
    events: &[ParsedSign1],
    extension: &ErasureEvidenceExportExtension,
    report: &mut VerificationReport,
) {
    let member_name = extension.catalog_ref.as_str();
    let Some(catalog_bytes) = archive.members.get(member_name) else {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::MissingErasureEvidenceCatalog,
            member_name.to_string(),
        ));
        return;
    };
    let actual_digest = sha256_bytes(catalog_bytes);
    if actual_digest.as_slice() != extension.catalog_digest.as_slice() {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::ErasureEvidenceCatalogDigestMismatch,
            member_name.to_string(),
        ));
    }

    let entries = match parse_erasure_catalog_entries(catalog_bytes) {
        Ok(entries) => entries,
        Err(error) => {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureEvidenceCatalogInvalid,
                format!("{member_name}/{error}"),
            ));
            return;
        }
    };

    if entries.len() as u64 != extension.entry_count {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::ErasureEvidenceCatalogInvalid,
            format!("{member_name}/entry_count"),
        ));
    }

    let mut event_by_hash: BTreeMap<[u8; 32], EventDetails> = BTreeMap::new();
    for event in events {
        if let Ok(details) = decode_event_details(event) {
            match event_by_hash.entry(details.canonical_event_hash) {
                Entry::Vacant(slot) => {
                    slot.insert(details);
                }
                Entry::Occupied(_) => {
                    report.event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ExportEventsDuplicateCanonicalHash,
                        hex_string(&details.canonical_event_hash),
                    ));
                }
            }
        }
    }

    let mut seen_hashes = BTreeSet::new();
    for row in &entries {
        if !seen_hashes.insert(row.canonical_event_hash) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureEvidenceCatalogDuplicateEvent,
                hex_string(&row.canonical_event_hash),
            ));
        }
    }

    for row in &entries {
        let Some(details) = event_by_hash.get(&row.canonical_event_hash) else {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureEvidenceCatalogEventUnresolved,
                hex_string(&row.canonical_event_hash),
            ));
            continue;
        };
        if details.event_type != ERASURE_EVIDENCE_EVENT_EXTENSION {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureEvidenceCatalogEventTypeMismatch,
                hex_string(&row.canonical_event_hash),
            ));
            continue;
        }
        if !erasure_catalog_row_matches_details(row, details) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::ErasureEvidenceCatalogMismatch,
                hex_string(&row.canonical_event_hash),
            ));
        }
    }
}
