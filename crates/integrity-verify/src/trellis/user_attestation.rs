use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use ed25519_dalek::ed25519::signature::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use trellis_types::{domain_separated_sha256, map_lookup_optional_value, map_lookup_text};

use super::USER_CONTENT_ATTESTATION_DOMAIN;
use crate::trellis::RecordValidator;
use crate::trellis::kinds::VerificationFailureKind;
use crate::trellis::parse::decode_value;
use crate::trellis::types::*;
use crate::trellis::util::{hex_string, is_identity_attestation_event_type, is_operator_uri};

/// Reads `admit_unverified_user_attestations` from a Posture Declaration's
/// dCBOR bytes. Per ADR 0010 §"Field semantics" `identity_attestation_ref`
/// clause and Core §28 CDDL, the field is OPTIONAL with a `false` default.
/// Returns `false` when the bytes don't decode as a map, or the field is
/// absent / null / not a bool — failing-closed to the default-required
/// posture so a malformed Posture Declaration cannot silently relax the
/// identity-required gate.
pub(crate) fn parse_admit_unverified_user_attestations(bytes: &[u8]) -> bool {
    let Ok(value) = decode_value(bytes) else {
        return false;
    };
    let Some(map) = value.as_map() else {
        return false;
    };
    matches!(
        map_lookup_optional_value(map, "admit_unverified_user_attestations"),
        Some(Value::Bool(true))
    )
}

/// Resolves the subject of an identity-attestation event from its
/// already-decoded `EventPayload.extensions` map. The Phase-1
/// deployment-local convention (mirrored in the fixture corpus) is to
/// put the subject URI at `extensions[event_type]["subject"]`, where
/// `event_type` is the identity-attestation extension key (registered
/// per Core §6.7; Phase-1 admission via [`is_identity_attestation_event_type`]).
/// Returns `Some(subject)` when resolvable, `None` for non-identity
/// events or for identity events whose payload omits the subject field
/// (that surfaces as `user_content_attestation_identity_subject_mismatch`
/// at the call site).
///
/// Reads from `EventPayload.extensions` directly — the `payload_ref.ciphertext`
/// bytes are an opaque content marker, not the extensions container, and
/// reading from there returns `None` for any well-formed event.
pub(crate) fn decode_identity_attestation_subject(
    extensions: &[(Value, Value)],
    event_type: &str,
    identity_event_type_admitted: &dyn Fn(&str) -> bool,
) -> Option<String> {
    if !is_identity_attestation_event_type(event_type) && !identity_event_type_admitted(event_type)
    {
        return None;
    }
    let identity_value = map_lookup_optional_value(extensions, event_type)?;
    let identity_map = identity_value.as_map()?;
    map_lookup_text(identity_map, "subject").ok()
}

/// Verifies the Ed25519 signature on a user-content-attestation payload
/// per ADR 0010 §"Verifier obligations" step 5. Re-hashes the
/// pre-computed `canonical_preimage` under domain tag
/// `trellis-user-content-attestation-v1` (Core §9.8) and verifies under
/// the public key resolved from `signing_kid`. Returns `Ok(true)` on
/// successful verification, `Ok(false)` on signature failure (caller
/// flips `signature_verified = false`), and `Err` on `signing_kid`
/// resolution failure (caller flips `key_active = false` with
/// `user_content_attestation_key_not_active`).
pub(crate) fn verify_user_content_attestation_signature(
    details: &UserContentAttestationDetails,
    public_key: &[u8; 32],
) -> bool {
    let signed_hash =
        domain_separated_sha256(USER_CONTENT_ATTESTATION_DOMAIN, &details.canonical_preimage);
    let signature = Signature::from_bytes(&details.signature);
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    verifying_key.verify(&signed_hash, &signature).is_ok()
}

fn signing_key_admits_user_content_attestation(
    entry: &SigningKeyEntry,
    attested_at: TrellisTimestamp,
) -> bool {
    let valid_to_ok = entry
        .valid_to
        .map(|valid_to| attested_at <= valid_to)
        .unwrap_or(true);
    match entry.status {
        0 => valid_to_ok,
        1 => {
            let valid_from_ok = entry
                .valid_from
                .map(|valid_from| valid_from <= attested_at)
                .unwrap_or(false);
            valid_from_ok && valid_to_ok
        }
        _ => false,
    }
}

/// ADR 0010 §"Verifier obligations" cross-event finalization. Step 1 + step 2
/// partial (CDDL + intra-payload invariants) run in
/// [`decode_user_content_attestation_payload`]; this pass runs steps 3
/// (chain-position resolution), 4 (identity resolution), 5 (signature
/// verification), 6 (key-state check), 7 (collision detection), 8
/// (operator-in-user-slot enforcement), and 9 (outcome accumulation).
///
/// **Posture Declaration handling.** Step 4's null-admission gate reads
/// `admit_unverified_user_attestations` from the Posture Declaration in
/// force at `attested_at`. The verifier passes the bytes through; absent
/// declaration defaults to `false` (REQUIRED non-null, fails-closed).
///
/// **Phase-1 identity-attestation taxonomy.** Step 4 admits any chain-present
/// event whose `event_type` matches the fixture-corpus deployment-local naming
/// or a consumer-owned taxonomy admitted by the `RecordValidator`. Resolved
/// event's `ledger_scope` MUST match the attestation's; `sequence` MUST be
/// strictly less than `attested_event_position`; payload subject MUST equal
/// `attestor`.
pub(crate) fn finalize_user_content_attestations(
    payloads: &[(usize, UserContentAttestationDetails, [u8; 32])],
    event_lookup_pool: &[EventDetails],
    event_by_hash_idx: &BTreeMap<[u8; 32], usize>,
    event_by_position_idx: &BTreeMap<(Vec<u8>, u64), usize>,
    registry: &BTreeMap<Vec<u8>, SigningKeyEntry>,
    posture_declaration: Option<&[u8]>,
    record_validator: &dyn RecordValidator,
    event_failures: &mut Vec<VerificationFailure>,
) -> Vec<UserContentAttestationOutcome> {
    if payloads.is_empty() {
        return Vec::new();
    }

    let event_by_hash = |hash: &[u8; 32]| {
        event_by_hash_idx
            .get(hash)
            .map(|&idx| &event_lookup_pool[idx])
    };

    // Step 7 collision detection. Two events sharing `attestation_id` with
    // disagreeing canonical payload fail closed. Use the same load-bearing
    // fields ADR 0010 §"Field semantics" `attestation_id` clause names as
    // collision-indicative: every signed field on the payload (excluding the
    // signature itself, which by construction differs whenever any signed
    // field differs).
    let mut id_to_canonical: BTreeMap<String, &UserContentAttestationDetails> = BTreeMap::new();
    let mut id_collision_reported: BTreeSet<String> = BTreeSet::new();
    for (_index, payload, canonical_hash) in payloads {
        match id_to_canonical.entry(payload.attestation_id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(payload);
            }
            Entry::Occupied(slot) => {
                let prior = *slot.get();
                let differs = prior.attested_event_hash != payload.attested_event_hash
                    || prior.attested_event_position != payload.attested_event_position
                    || prior.attestor != payload.attestor
                    || prior.identity_attestation_ref != payload.identity_attestation_ref
                    || prior.signing_intent != payload.signing_intent
                    || prior.attested_at != payload.attested_at;
                if differs && id_collision_reported.insert(payload.attestation_id.clone()) {
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::UserContentAttestationIdCollision,
                        hex_string(canonical_hash),
                    ));
                }
            }
        }
    }

    let mut outcomes: Vec<UserContentAttestationOutcome> = Vec::with_capacity(payloads.len());

    for (index, payload, canonical_hash) in payloads {
        let mut outcome = UserContentAttestationOutcome {
            attestation_id: payload.attestation_id.clone(),
            attested_event_hash: payload.attested_event_hash,
            attestor: payload.attestor.clone(),
            signing_intent: payload.signing_intent.clone(),
            event_index: *index as u64,
            chain_position_resolved: true,
            identity_resolved: true,
            signature_verified: true,
            key_active: true,
            failures: Vec::new(),
        };

        // Step 2 deferred-failure surface. Per ADR 0010 §"Verifier
        // obligations" step 2, intra-payload-invariant failures
        // (`user_content_attestation_intent_malformed` /
        // `user_content_attestation_timestamp_mismatch`) flip
        // `integrity_verified = false` only — they are NOT structure
        // failures. The decoder set the marker; finalize raises it as an
        // `event_failure` and skips remaining per-event checks for this
        // attestation. Outcome accumulates the failure so the §9 report
        // reflects it; subsequent per-step booleans stay `true` because
        // the steps weren't run, not because they passed.
        if let Some(kind) = payload.step_2_failure {
            outcome.failures.push(kind.as_str().to_string());
            event_failures.push(VerificationFailure::new(kind, hex_string(canonical_hash)));
            outcomes.push(outcome);
            continue;
        }

        // Step 8 — operator-in-user-slot enforcement. Companion §6.4
        // operator URIs MUST NOT appear in `attestor` slots of
        // user-content-attestation events.
        if is_operator_uri(&payload.attestor) {
            outcome
                .failures
                .push("user_content_attestation_operator_in_user_slot".into());
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::UserContentAttestationOperatorInUserSlot,
                hex_string(canonical_hash),
            ));
        }

        // Step 3 — chain-position resolution. `attested_event_position` MUST
        // resolve to a chain-present event in scope whose
        // `canonical_event_hash` equals `attested_event_hash`. To find the
        // host scope we use the attestation event's own scope (caller is
        // expected to feed events from one ledger; cross-scope lookup is
        // out of step 3's scope).
        //
        // We recover the attestation event's scope from `event_by_hash`
        // because `payloads` doesn't carry scope alongside the attestation
        // canonical hash directly; the chain-loop already populated that
        // index above.
        let attestation_scope = event_by_hash(canonical_hash)
            .map(|d| d.scope.clone())
            .unwrap_or_default();
        let host_lookup_key = (attestation_scope, payload.attested_event_position);
        match event_by_position_idx
            .get(&host_lookup_key)
            .map(|&idx| &event_lookup_pool[idx])
        {
            Some(host) if host.canonical_event_hash == payload.attested_event_hash => {}
            Some(_) | None => {
                outcome.chain_position_resolved = false;
                outcome
                    .failures
                    .push("user_content_attestation_chain_position_mismatch".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::UserContentAttestationChainPositionMismatch,
                    hex_string(canonical_hash),
                ));
            }
        }

        // Step 4 — identity resolution.
        if let Some(identity_ref) = payload.identity_attestation_ref {
            // Non-null path: resolve to a chain-present event of a
            // registered identity-attestation event type, scope match,
            // sequence-strictly-less-than-attested_event_position, subject
            // equals attestor.
            match event_by_hash(&identity_ref) {
                None => {
                    outcome.identity_resolved = false;
                    outcome
                        .failures
                        .push("user_content_attestation_identity_unresolved".into());
                    event_failures.push(VerificationFailure::new(
                        VerificationFailureKind::UserContentAttestationIdentityUnresolved,
                        hex_string(&identity_ref),
                    ));
                }
                Some(identity_event) => {
                    if !is_identity_attestation_event_type(&identity_event.event_type)
                        && !record_validator
                            .admits_identity_attestation_event_type(&identity_event.event_type)
                    {
                        outcome.identity_resolved = false;
                        outcome
                            .failures
                            .push("user_content_attestation_identity_unresolved".into());
                        event_failures.push(VerificationFailure::new(
                            VerificationFailureKind::UserContentAttestationIdentityUnresolved,
                            hex_string(&identity_ref),
                        ));
                    } else {
                        // Scope match check. The attestation's scope (from
                        // `event_by_hash`) must equal the identity event's.
                        let attestation_scope_for_identity = event_by_hash(canonical_hash)
                            .map(|d| d.scope.clone())
                            .unwrap_or_default();
                        if identity_event.scope != attestation_scope_for_identity {
                            outcome.identity_resolved = false;
                            outcome
                                .failures
                                .push("user_content_attestation_identity_unresolved".into());
                            event_failures.push(VerificationFailure::new(
                                VerificationFailureKind::UserContentAttestationIdentityUnresolved,
                                hex_string(&identity_ref),
                            ));
                        } else if identity_event.sequence >= payload.attested_event_position {
                            // Temporal precedence: identity proof MUST
                            // strictly precede the attestation.
                            outcome.identity_resolved = false;
                            outcome.failures.push(
                                "user_content_attestation_identity_temporal_inversion".into(),
                            );
                            event_failures.push(VerificationFailure::new(
                                VerificationFailureKind::UserContentAttestationIdentityTemporalInversion,
                                hex_string(&identity_ref),
                            ));
                        } else {
                            // Subject match check — read the subject the
                            // decoder extracted from the resolved event's
                            // EventPayload.extensions map. External-payload
                            // identity events can extend this to fetch from
                            // payload_blobs; Phase-1 inline events carry the
                            // subject directly.
                            match identity_event.identity_attestation_subject() {
                                Some(s) if s == payload.attestor => {}
                                _ => {
                                    outcome.identity_resolved = false;
                                    outcome.failures.push(
                                        "user_content_attestation_identity_subject_mismatch".into(),
                                    );
                                    event_failures.push(VerificationFailure::new(
                                        VerificationFailureKind::UserContentAttestationIdentitySubjectMismatch,
                                        hex_string(&identity_ref),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Null path: deployment Posture Declaration MUST declare
            // `admit_unverified_user_attestations: true`. Default-required
            // (false / absent / malformed declaration) flips
            // `user_content_attestation_identity_required`.
            let admitted = posture_declaration
                .map(parse_admit_unverified_user_attestations)
                .unwrap_or(false);
            if !admitted {
                outcome.identity_resolved = false;
                outcome
                    .failures
                    .push("user_content_attestation_identity_required".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::UserContentAttestationIdentityRequired,
                    hex_string(canonical_hash),
                ));
            }
        }

        // Step 6 — key-state check (run BEFORE step 5 so a wrong-class /
        // wrong-state kid surfaces its own failure code rather than masking
        // as a signature failure).
        let key_entry = registry.get(&payload.signing_kid);
        let key_active = match key_entry {
            None => false,
            Some(entry) => signing_key_admits_user_content_attestation(entry, payload.attested_at),
        };
        if !key_active {
            outcome.key_active = false;
            outcome
                .failures
                .push("user_content_attestation_key_not_active".into());
            event_failures.push(VerificationFailure::new(
                VerificationFailureKind::UserContentAttestationKeyNotActive,
                hex_string(canonical_hash),
            ));
        }

        // Step 5 — signature verification under
        // `trellis-user-content-attestation-v1`. Skipped when `key_active =
        // false` because we have no public key; the verifier reports
        // `key_not_active` and downstream tooling treats that as the
        // dominant failure (no need to redundantly flag
        // `signature_invalid`).
        if let Some(entry) = key_entry
            && key_active
        {
            let ok = verify_user_content_attestation_signature(payload, &entry.public_key);
            if !ok {
                outcome.signature_verified = false;
                outcome
                    .failures
                    .push("user_content_attestation_signature_invalid".into());
                event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::UserContentAttestationSignatureInvalid,
                    hex_string(canonical_hash),
                ));
            }
        }

        outcomes.push(outcome);
    }

    outcomes
}
