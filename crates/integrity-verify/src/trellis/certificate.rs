use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use trellis_types::{domain_separated_sha256, sha256_bytes};

use super::{CERTIFICATE_EVENT_EXTENSION, PRESENTATION_ARTIFACT_DOMAIN};
use crate::trellis::certificate_proof::ResponseProofResolver;
use crate::trellis::kinds::VerificationFailureKind;
use crate::trellis::parse::{decode_event_details, parse_certificate_catalog_entries};
use crate::trellis::types::*;
use crate::trellis::util::hex_string;

/// ADR 0007 §"Verifier obligations" cross-event finalization. Step 1 runs
/// in [`decode_certificate_payload`] (CDDL + per-event chain-summary
/// invariants); this pass runs steps 2 (id collision + workflow_status /
/// impact_level / covered_claims registry — Phase-1 admit-any-tstr posture),
/// 5 (signing-event resolution), 6 (timestamp equivalence), and 8
/// (outcome accumulation).
///
/// **Phase-1 chain-context posture.** Step 5 / 6 / 7 require the full event
/// list to resolve `signing_events[i]` digests against in-chain signing
/// events. The genesis-append code paths
/// (`verify_single_event` / `verify_tampered_ledger`) frequently pass a
/// minimal `events` slice that does not include the referenced signing
/// events; in that case `signing_event_unresolved` would false-positive on
/// vectors whose contract is "this one event decodes". Posture: when an
/// event in `events` matches a `signing_events[i]` digest, run the cross
/// checks; when it does not, accumulate the outcome with
/// `all_signing_events_resolved = false` ONLY if the export-bundle context
/// is in scope. The export-bundle path runs the full `verify_event_set_with_classes`
/// over all events, so chain context is complete and step 5 / 6 / 7 are
/// authoritative there. Step 4 (attachment lineage) is wholly deferred to
/// the export-bundle path — see [`verify_certificate_attachment_lineage`].
///
/// Step 2 covered_claims / workflow_status / impact_level enum-extension
/// gating: per ADR 0007 §"Field semantics" Phase-1 reference verifier
/// admits any registered `tstr` shape; deep registry-membership rides
/// follow-on milestones alongside WOS signature-profile registry plumbing.
/// `certificate_covered_claim_unknown` and `certificate_enum_extension_unknown`
/// reserve their tamper_kind in §19.1 for that evolution.
pub(crate) fn finalize_certificates_of_completion(
    payloads: &[(usize, CertificateDetails, [u8; 32])],
    event_lookup_pool: &[EventDetails],
    event_by_hash_idx: &BTreeMap<[u8; 32], usize>,
    payload_blobs: Option<&BTreeMap<[u8; 32], Vec<u8>>>,
    resolver: &dyn ResponseProofResolver,
    event_failures: &mut Vec<VerificationFailure>,
) -> Vec<CertificateOfCompletionOutcome> {
    if payloads.is_empty() {
        return Vec::new();
    }

    let event_by_hash = |hash: &[u8; 32]| {
        event_by_hash_idx
            .get(hash)
            .map(|&idx| &event_lookup_pool[idx])
    };

    // Step 2 second sub-clause: certificate_id collision detection across
    // the certificate event set in scope. "Differ" is canonical-payload
    // disagreement; for the Phase-1 reference verifier we compare
    // `(content_hash, signing_events, signer_count, completed_at,
    // workflow_status)` because those are the load-bearing fields that
    // ADR 0007 §"Field semantics" identifies as collision-indicative.
    let mut id_to_canonical: BTreeMap<String, &CertificateDetails> = BTreeMap::new();
    let mut id_collision_reported: BTreeSet<String> = BTreeSet::new();
    for (_index, payload, canonical_hash) in payloads {
        match id_to_canonical.entry(payload.certificate_id.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(payload);
            }
            std::collections::btree_map::Entry::Occupied(slot) => {
                let prior = *slot.get();
                let differs = prior.presentation_artifact.content_hash
                    != payload.presentation_artifact.content_hash
                    || prior.signing_events != payload.signing_events
                    || prior.chain_summary.signer_count != payload.chain_summary.signer_count
                    || prior.completed_at != payload.completed_at
                    || prior.chain_summary.workflow_status != payload.chain_summary.workflow_status;
                if differs && id_collision_reported.insert(payload.certificate_id.clone()) {
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::CertificateIdCollision,
                        hex_string(canonical_hash),
                    ));
                }
            }
        }
    }

    let mut outcomes: Vec<CertificateOfCompletionOutcome> = Vec::with_capacity(payloads.len());

    for (index, payload, canonical_hash) in payloads {
        let mut outcome = CertificateOfCompletionOutcome {
            certificate_id: payload.certificate_id.clone(),
            event_index: *index as u64,
            completed_at: payload.completed_at,
            signer_count: payload.chain_summary.signer_count,
            // Step 4 (attachment lineage + content recompute) is the
            // export-bundle path's responsibility. Genesis-append context:
            // mark `attachment_resolved = true` so the §19 step-9 fold
            // doesn't false-positive on minimal-genesis fixtures. The
            // export-bundle path overrides this via
            // `verify_certificate_attachment_lineage`.
            attachment_resolved: true,
            all_signing_events_resolved: true,
            chain_summary_consistent: true,
            failures: Vec::new(),
        };

        // Step 3 (Phase-1 structural attestation contract): if any row was
        // malformed at decode time, surface as `attestation_insufficient`
        // (existing code reused per ADR 0007 §"Verifier obligations" step 3).
        // Crypto verification rides Phase-2+.
        if !payload.attestation_signatures_well_formed {
            outcome.chain_summary_consistent = false;
            outcome.failures.push("attestation_insufficient".into());
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::AttestationInsufficient,
                hex_string(canonical_hash),
            ));
        }

        // Steps 5 / 6 / 7 — each `signing_events[i]` digest cross-checked
        // against the chain. When the slice does not carry the referenced
        // event, treat it as unresolvable (export-bundle context) — the
        // export-bundle path is the authoritative caller because it carries
        // the full chain. Genesis-append context lacks chain visibility;
        // see the docstring on this fn.
        for (i, signing_event_hash) in payload.signing_events.iter().enumerate() {
            let resolved = event_by_hash(signing_event_hash);
            let Some(target) = resolved else {
                outcome.all_signing_events_resolved = false;
                outcome.failures.push("signing_event_unresolved".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::SigningEventUnresolved,
                    hex_string(signing_event_hash),
                ));
                continue;
            };
            let display = &payload.chain_summary.signer_display[i];
            let Some(payload_bytes) = readable_payload_for_certificate(target, payload_blobs)
            else {
                outcome.all_signing_events_resolved = false;
                outcome.failures.push("signing_event_unresolved".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::SigningEventUnresolved,
                    hex_string(signing_event_hash),
                ));
                continue;
            };
            if let Some(principal_ref) = resolver.resolve_principal_ref(&payload_bytes)
                && display.principal_ref != principal_ref
            {
                outcome.chain_summary_consistent = false;
                outcome
                    .failures
                    .push("certificate_chain_summary_mismatch".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::CertificateChainSummaryMismatch,
                    hex_string(canonical_hash),
                ));
            }
            // Step 6: signed_at MUST equal authored_at (timestamp exact, no skew).
            if display.signed_at != target.authored_at {
                outcome.chain_summary_consistent = false;
                outcome
                    .failures
                    .push("signing_event_timestamp_mismatch".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::SigningEventTimestampMismatch,
                    hex_string(signing_event_hash),
                ));
            }
        }

        if let Some(response_ref) = payload.chain_summary.response_ref {
            let mut matched = false;
            let mut had_resolvable_response = false;
            for signing_event_hash in &payload.signing_events {
                let Some(target) = event_by_hash(signing_event_hash) else {
                    continue;
                };
                let Some(payload_bytes) = readable_payload_for_certificate(target, payload_blobs)
                else {
                    continue;
                };
                let record_response_hash = match resolver.resolve(&payload_bytes) {
                    Ok(Some(proof)) => proof.response_hash,
                    Ok(None) => continue,
                    Err(
                        crate::trellis::certificate_proof::ResolverError::MalformedResponseDigest(
                            _,
                        ),
                    ) => {
                        // Phase N: a payload that declared a sha-256 response
                        // digest but carried it in non-hex form fails closed
                        // with a distinct kind, localized to the certificate
                        // event whose response_ref triggered the lookup.
                        outcome.chain_summary_consistent = false;
                        outcome.failures.push("malformed_response_digest".into());
                        event_failures.push(VerificationFailure::new(
                            VerificationFailureKind::MalformedResponseDigest,
                            hex_string(canonical_hash),
                        ));
                        continue;
                    }
                };
                had_resolvable_response = true;
                if record_response_hash == response_ref {
                    matched = true;
                    break;
                }
            }
            if had_resolvable_response && !matched {
                outcome.chain_summary_consistent = false;
                outcome.failures.push("response_ref_mismatch".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::ResponseRefMismatch,
                    hex_string(canonical_hash),
                ));
            }
        }

        outcomes.push(outcome);
    }

    outcomes
}

fn readable_payload_for_certificate(
    target: &EventDetails,
    payload_blobs: Option<&BTreeMap<[u8; 32], Vec<u8>>>,
) -> Option<Vec<u8>> {
    match &target.payload_ref {
        PayloadRef::Inline(bytes) => Some(bytes.clone()),
        PayloadRef::External => {
            payload_blobs.and_then(|blobs| blobs.get(&target.content_hash).cloned())
        }
    }
}

/// Field-wise agreement check between a catalog row and the in-chain
/// certificate event's decoded payload. Mirror of
/// [`erasure_catalog_row_matches_details`].
pub(crate) fn certificate_catalog_row_matches_details(
    row: &CertificateCatalogEntryRow,
    details: &EventDetails,
) -> bool {
    let Some(certificate) = details.certificate() else {
        return false;
    };
    if row.canonical_event_hash != details.canonical_event_hash {
        return false;
    }
    if row.certificate_id != certificate.certificate_id {
        return false;
    }
    if row.completed_at != certificate.completed_at {
        return false;
    }
    if row.signer_count != certificate.chain_summary.signer_count {
        return false;
    }
    if row.media_type != certificate.presentation_artifact.media_type {
        return false;
    }
    if row.attachment_id != certificate.presentation_artifact.attachment_id {
        return false;
    }
    if row.workflow_status != certificate.chain_summary.workflow_status {
        return false;
    }
    true
}

/// Verifies the optional `065-certificates-of-completion.cbor` catalog
/// (ADR 0007 §"Export manifest catalog" / Core §19 step 6c optional catalog).
/// Mirror of [`verify_erasure_evidence_catalog`].
pub(crate) fn verify_certificate_catalog(
    archive: &ExportArchive,
    events: &[ParsedSign1],
    extension: &CertificateExportExtension,
    report: &mut VerificationReport,
) {
    let member_name = extension.catalog_ref.as_str();
    let Some(catalog_bytes) = archive.members.get(member_name) else {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::MissingCertificateCatalog,
            member_name.to_string(),
        ));
        return;
    };
    // Catalog digest under `trellis-content-v1` (Core §19 step 6c optional
    // catalog clause; same domain tag as the existing catalog patterns —
    // re-verified via raw SHA-256 since `sha256_bytes` covers the
    // bare-bytes path that the manifest's binding uses).
    let actual_digest = sha256_bytes(catalog_bytes);
    if actual_digest.as_slice() != extension.catalog_digest.as_slice() {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::CertificateCatalogDigestMismatch,
            member_name.to_string(),
        ));
    }

    let entries = match parse_certificate_catalog_entries(catalog_bytes) {
        Ok(entries) => entries,
        Err(error) => {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::CertificateCatalogInvalid,
                format!("{member_name}/{error}"),
            ));
            return;
        }
    };

    if entries.len() as u64 != extension.entry_count {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::CertificateCatalogInvalid,
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
                VerificationFailureKind::CertificateCatalogDuplicateEvent,
                hex_string(&row.canonical_event_hash),
            ));
        }
    }

    for row in &entries {
        let Some(details) = event_by_hash.get(&row.canonical_event_hash) else {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::CertificateCatalogEventUnresolved,
                hex_string(&row.canonical_event_hash),
            ));
            continue;
        };
        // Per Core §6.7 the certificate-of-completion event's `event_type`
        // mirrors the extension key. Mirrors how the erasure-evidence
        // catalog cross-checks `details.event_type ==
        // ERASURE_EVIDENCE_EVENT_EXTENSION`.
        if details.event_type != CERTIFICATE_EVENT_EXTENSION {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::CertificateCatalogEventTypeMismatch,
                hex_string(&row.canonical_event_hash),
            ));
            continue;
        }
        if !certificate_catalog_row_matches_details(row, details) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::CertificateCatalogMismatch,
                hex_string(&row.canonical_event_hash),
            ));
        }
    }
}

/// ADR 0007 §"Verifier obligations" step 4 — attachment lineage resolution and
/// content-hash recompute in the export-bundle path (requires attachment-binding
/// lineage per ADR 0072 and the payload blobs map).
///
/// For each in-scope certificate event:
///
/// - resolve `presentation_artifact.attachment_id` via the chain's
///   `trellis.evidence-attachment-binding.v1` events;
/// - recover the bound attachment bytes from `payload_blobs`;
/// - recompute SHA-256 over the bytes under domain tag
///   `trellis-presentation-artifact-v1` (§9.8) and confirm it equals
///   `presentation_artifact.content_hash`.
///
/// Failure surfaces: `presentation_artifact_attachment_missing` (lineage
/// unresolvable / bytes absent) — distinct from
/// `presentation_artifact_content_mismatch` (lineage resolved, hash
/// disagrees). Both flip `outcome.attachment_resolved` for the §19 step-9
/// fold; the dominant tamper_kind is the most-specific available.
pub(crate) fn verify_certificate_attachment_lineage(
    events: &[ParsedSign1],
    payload_blobs: &BTreeMap<[u8; 32], Vec<u8>>,
    report: &mut VerificationReport,
) {
    if report.certificates_of_completion.is_empty() {
        return;
    }

    // Build (attachment_id → AttachmentBindingDetails + EventDetails) map.
    // ADR 0072 lineage: a certificate's `presentation_artifact.attachment_id`
    // must map to exactly one binding event whose extension carries the
    // matching `attachment_id`. Phase-1 lineage resolution is the latest
    // binding for that id (forward-walk; `prior_binding_hash` chain not
    // material for content-hash recompute — the latest binding IS the bound
    // bytes by definition).
    let mut binding_by_attachment_id: BTreeMap<String, (AttachmentBindingDetails, [u8; 32])> =
        BTreeMap::new();
    for event in events {
        if let Ok(details) = decode_event_details(event)
            && let Some(binding) = details.attachment_binding()
        {
            binding_by_attachment_id.insert(
                binding.attachment_id.clone(),
                (binding.clone(), details.content_hash),
            );
        }
    }

    // Build (global event index → EventDetails) map for certificate
    // events. The outcome's `event_index` is the GLOBAL position in `events`
    // (set by `verify_event_set_with_classes` when it pushes to
    // `certificate_payloads`), so we must index against the unfiltered
    // event list — a previous filtered-collect-then-Vec::get(event_index)
    // shape silently false-positived `presentation_artifact_attachment_missing`
    // on multi-event chains where binding/sigaff events sit BEFORE the
    // certificate (e.g. `[binding, sigaff, certificate]` → `event_index = 2`
    // while a filtered cert-only Vec has length 1).
    let mut cert_events_by_index: BTreeMap<usize, EventDetails> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if let Ok(details) = decode_event_details(event)
            && details.certificate().is_some()
        {
            cert_events_by_index.insert(index, details);
        }
    }

    for outcome in report.certificates_of_completion.iter_mut() {
        let Some(details) = cert_events_by_index.get(&(outcome.event_index as usize)) else {
            // Index out of range — the underlying event vector changed
            // shape between collection and lineage check. Treat as
            // unresolvable; do not mask with attachment_resolved=true.
            outcome.attachment_resolved = false;
            outcome
                .failures
                .push("presentation_artifact_attachment_missing".into());
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::PresentationArtifactAttachmentMissing,
                outcome.certificate_id.clone(),
            ));
            continue;
        };
        let canonical_hash_hex = hex_string(&details.canonical_event_hash);
        let Some(certificate) = details.certificate() else {
            continue;
        };

        let Some((binding, _binding_payload_hash)) =
            binding_by_attachment_id.get(&certificate.presentation_artifact.attachment_id)
        else {
            outcome.attachment_resolved = false;
            outcome
                .failures
                .push("presentation_artifact_attachment_missing".into());
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::PresentationArtifactAttachmentMissing,
                canonical_hash_hex,
            ));
            continue;
        };

        // Resolve attachment bytes via `payload_blobs` keyed on
        // `binding.payload_content_hash` (the content_hash of the binding
        // event's payload, which is the ADR 0072 mechanism for naming the
        // ciphertext member in `060-payloads/<digest>.bin`).
        let Some(attachment_bytes) = payload_blobs.get(&binding.payload_content_hash) else {
            outcome.attachment_resolved = false;
            outcome
                .failures
                .push("presentation_artifact_attachment_missing".into());
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::PresentationArtifactAttachmentMissing,
                canonical_hash_hex,
            ));
            continue;
        };

        // Recompute content hash under `trellis-presentation-artifact-v1`
        // and compare with `presentation_artifact.content_hash`.
        let recomputed = domain_separated_sha256(PRESENTATION_ARTIFACT_DOMAIN, attachment_bytes);
        if recomputed != certificate.presentation_artifact.content_hash {
            outcome.attachment_resolved = false;
            outcome
                .failures
                .push("presentation_artifact_content_mismatch".into());
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::PresentationArtifactContentMismatch,
                canonical_hash_hex,
            ));
        }
    }
}
