use std::collections::BTreeMap;

use ciborium::Value;
use trellis_types::{
    ArtifactType, decode_cbor_value, map_lookup_array, map_lookup_bool, map_lookup_bytes,
    map_lookup_fixed_bytes, map_lookup_map, map_lookup_optional_bytes,
    map_lookup_optional_fixed_bytes, map_lookup_optional_map, map_lookup_optional_text,
    map_lookup_optional_value, map_lookup_text, map_lookup_u64,
};

use super::{
    ATTACHMENT_EVENT_EXTENSION, ATTACHMENT_EXPORT_EXTENSION, CERTIFICATE_EVENT_EXTENSION,
    CERTIFICATE_EXPORT_EXTENSION, ERASURE_EVIDENCE_EVENT_EXTENSION,
    ERASURE_EVIDENCE_EXPORT_EXTENSION, OPEN_CLOCKS_EXPORT_EXTENSION, RESERVED_NON_SIGNING_KIND,
    SEAL_FENCE_EXPORT_EXTENSION, SUPERSEDES_CHAIN_ID_EVENT_EXTENSION,
    SUPERSESSION_GRAPH_EXPORT_EXTENSION, USER_CONTENT_ATTESTATION_EVENT_EXTENSION,
};
use crate::trellis::kinds::{VerificationFailureKind, VerifyErrorKind};
use crate::trellis::merkle::recompute_canonical_event_hash;
use crate::trellis::types::*;
use crate::trellis::user_attestation::decode_identity_attestation_subject;
use crate::trellis::util::{
    bytes_array, is_syntactically_valid_uri, parse_sha256_text, validate_subject_scope_shape,
};

pub(crate) fn parse_sign1_array(bytes: &[u8]) -> Result<Vec<ParsedSign1>, VerifyError> {
    let value = decode_value(bytes)?;
    let items = value
        .as_array()
        .ok_or_else(|| VerifyError::new("expected a dCBOR array"))?;
    items.iter().map(parse_sign1_value).collect()
}

pub(crate) fn parse_sign1_bytes(bytes: &[u8]) -> Result<ParsedSign1, VerifyError> {
    let value = decode_value(bytes)?;
    parse_sign1_value(&value)
}

pub(crate) fn parse_sign1_value(value: &Value) -> Result<ParsedSign1, VerifyError> {
    let sign1 = integrity_cose::decode_cose_sign1_value(value).map_err(|error| {
        let message = error.to_string();
        if message.contains("RetiredDispatchLabelPresent") {
            VerifyError::with_kind(message, VerifyErrorKind::MalformedCose)
        } else {
            VerifyError::new(message)
        }
    })?;
    let kid = sign1
        .kid()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| VerifyError::new("missing COSE label 4 bytes"))?;
    let alg = sign1
        .alg()
        .ok_or_else(|| VerifyError::new("missing COSE label 1 integer"))?;
    let suite_id = sign1
        .suite_id()
        .map(i128::from)
        .ok_or_else(|| VerifyError::new("missing COSE label -65537 integer"))?;
    let artifact_type = sign1
        .artifact_type()
        .ok_or_else(|| {
            VerifyError::with_kind(
                "ArtifactTypeMissing: missing COSE label -65538 artifact_type",
                VerifyErrorKind::MalformedCose,
            )
        })
        .and_then(|value| {
            ArtifactType::from_cose_value(value).map_err(|error| {
                VerifyError::with_kind(
                    format!("ArtifactTypeUnknown: {error}"),
                    VerifyErrorKind::MalformedCose,
                )
            })
        })?;
    let signature: [u8; 64] = sign1
        .signature()
        .try_into()
        .map_err(|_| VerifyError::new("signature is not 64 bytes"))?;

    Ok(ParsedSign1 {
        protected_bytes: sign1.protected_header().to_vec(),
        kid,
        alg,
        suite_id,
        artifact_type,
        payload: sign1.payload().map(<[u8]>::to_vec),
        signature,
    })
}

pub(crate) fn decode_event_details(event: &ParsedSign1) -> Result<EventDetails, VerifyError> {
    decode_event_details_with_identity_admission(event, &|_| false)
}

pub(crate) fn decode_event_details_with_identity_admission(
    event: &ParsedSign1,
    identity_event_type_admitted: &dyn Fn(&str) -> bool,
) -> Result<EventDetails, VerifyError> {
    let payload_bytes = event
        .payload
        .as_ref()
        .ok_or_else(|| VerifyError::new("detached event payloads are out of scope"))?;
    let payload_value = decode_value(payload_bytes)?;
    let payload_map = payload_value
        .as_map()
        .ok_or_else(|| VerifyError::new("event payload root is not a map"))?;
    let scope = map_lookup_bytes(payload_map, "ledger_scope")?;
    let sequence = map_lookup_u64(payload_map, "sequence")?;
    let prev_hash =
        map_lookup_optional_bytes(payload_map, "prev_hash")?.map(|bytes| bytes_array(&bytes));
    let author_event_hash = bytes_array(&map_lookup_fixed_bytes(
        payload_map,
        "author_event_hash",
        32,
    )?);
    let content_hash = bytes_array(&map_lookup_fixed_bytes(payload_map, "content_hash", 32)?);
    let canonical_event_hash = recompute_canonical_event_hash(&scope, payload_bytes);

    // Core §6.1 / §17.2 — `idempotency_key` MUST be a CBOR byte string of
    // 1..=64 bytes. Length-bound violations surface as the typed §17.5
    // `idempotency_key_length_invalid` so the report's `tamper_kind`
    // localizes the structural failure.
    let idempotency_key = map_lookup_bytes(payload_map, "idempotency_key")?;
    if idempotency_key.is_empty() || idempotency_key.len() > 64 {
        return Err(VerifyError::with_kind(
            format!(
                "idempotency_key length {} outside Core §6.1 / §17.2 bound 1..=64",
                idempotency_key.len(),
            ),
            VerifyErrorKind::IdempotencyKeyLengthInvalid,
        ));
    }

    let header = map_lookup_map(payload_map, "header")?;
    let authored_at = map_lookup_timestamp(header, "authored_at")?;
    let event_type_bytes = map_lookup_bytes(header, "event_type")?;
    let event_type = String::from_utf8(event_type_bytes)
        .map_err(|_| VerifyError::new("header.event_type is not valid UTF-8"))?;
    let classification_bytes = map_lookup_bytes(header, "classification")?;
    let classification = String::from_utf8(classification_bytes)
        .map_err(|_| VerifyError::new("header.classification is not valid UTF-8"))?;

    let payload_ref_map = map_lookup_map(payload_map, "payload_ref")?;
    let payload_ref = match map_lookup_text(payload_ref_map, "ref_type")?.as_str() {
        "inline" => PayloadRef::Inline(map_lookup_bytes(payload_ref_map, "ciphertext")?),
        "external" => PayloadRef::External,
        _ => {
            return Err(VerifyError::new(
                "payload_ref.ref_type is not a supported Phase-1 value",
            ));
        }
    };

    let profile_extensions = match map_lookup_optional_map(payload_map, "extensions")? {
        Some(extensions) => decode_profile_extensions(
            extensions,
            authored_at,
            &event_type,
            identity_event_type_admitted,
        )?,
        None => ProfileExtensionMap::new(),
    };
    let wrap_recipients = decode_key_bag_recipients(payload_map)?;

    Ok(EventDetails {
        scope,
        sequence,
        authored_at,
        event_type,
        classification,
        prev_hash,
        author_event_hash,
        content_hash,
        canonical_event_hash,
        idempotency_key,
        payload_ref,
        profile_extensions,
        wrap_recipients,
    })
}

fn decode_profile_extensions(
    extensions: &[(Value, Value)],
    authored_at: TrellisTimestamp,
    event_type: &str,
    identity_event_type_admitted: &dyn Fn(&str) -> bool,
) -> Result<ProfileExtensionMap, VerifyError> {
    let mut decoded = ProfileExtensionMap::new();
    if let Some(transition) = decode_transition_details(extensions)? {
        decoded.insert(
            ProfileExtensionKind::Transition,
            ProfileExtensionDetails::Transition(transition),
        );
    }
    if let Some(binding) = decode_attachment_binding_details(extensions)? {
        decoded.insert(
            ProfileExtensionKind::AttachmentBinding,
            ProfileExtensionDetails::AttachmentBinding(binding),
        );
    }
    if let Some(erasure) = decode_erasure_evidence_details(extensions, authored_at)? {
        decoded.insert(
            ProfileExtensionKind::ErasureEvidence,
            ProfileExtensionDetails::ErasureEvidence(erasure),
        );
    }
    if let Some(certificate) = decode_certificate_payload(extensions)? {
        decoded.insert(
            ProfileExtensionKind::CertificateOfCompletion,
            ProfileExtensionDetails::CertificateOfCompletion(certificate),
        );
    }
    if let Some(attestation) = decode_user_content_attestation_payload(extensions, authored_at)? {
        decoded.insert(
            ProfileExtensionKind::UserContentAttestation,
            ProfileExtensionDetails::UserContentAttestation(attestation),
        );
    }
    if let Some(subject) =
        decode_identity_attestation_subject(extensions, event_type, identity_event_type_admitted)
    {
        decoded.insert(
            ProfileExtensionKind::IdentityAttestationSubject,
            ProfileExtensionDetails::IdentityAttestationSubject(subject),
        );
    }
    if let Some(supersedes_chain) = decode_supersedes_chain_id_payload(extensions)? {
        decoded.insert(
            ProfileExtensionKind::SupersedesChainId,
            ProfileExtensionDetails::SupersedesChainId(supersedes_chain),
        );
    }
    Ok(decoded)
}

pub(crate) fn decode_supersedes_chain_id_payload(
    extensions: &[(Value, Value)],
) -> Result<Option<SupersedesChainIdDetails>, VerifyError> {
    let Some(extension_value) =
        map_lookup_optional_value(extensions, SUPERSEDES_CHAIN_ID_EVENT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("supersedes-chain-id extension is not a map"))?;
    Ok(Some(SupersedesChainIdDetails {
        chain_id: map_lookup_bytes(extension_map, "chain_id")?,
        checkpoint_hash: bytes_array(&map_lookup_fixed_bytes(
            extension_map,
            "checkpoint_hash",
            32,
        )?),
    }))
}

/// Extracts wrap recipients from `payload.key_bag.entries[*].recipient` so
/// step 8 (post_erasure_wrap detection) can compare against `kid_destroyed`.
/// Returns an empty vec when `key_bag` is missing or has no entries (Phase-1
/// plaintext path). Recipients are opaque bytes per Core §9.4 — comparison
/// is byte-equality with the 16-byte `kid_destroyed` in step 8.
pub(crate) fn decode_key_bag_recipients(
    payload_map: &[(Value, Value)],
) -> Result<Vec<Vec<u8>>, VerifyError> {
    let Some(key_bag_value) = map_lookup_optional_value(payload_map, "key_bag") else {
        return Ok(Vec::new());
    };
    let key_bag = match key_bag_value {
        Value::Map(map) => map.as_slice(),
        Value::Null => return Ok(Vec::new()),
        _ => return Err(VerifyError::new("key_bag is neither a map nor null")),
    };
    let Some(entries_value) = map_lookup_optional_value(key_bag, "entries") else {
        return Ok(Vec::new());
    };
    let entries = match entries_value {
        Value::Array(array) => array,
        Value::Null => return Ok(Vec::new()),
        _ => {
            return Err(VerifyError::new(
                "key_bag.entries is neither an array nor null",
            ));
        }
    };
    let mut recipients = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry_map = entry
            .as_map()
            .ok_or_else(|| VerifyError::new("key_bag entry is not a map"))?;
        let recipient = map_lookup_bytes(entry_map, "recipient")?;
        recipients.push(recipient);
    }
    Ok(recipients)
}

pub(crate) fn decode_transition_details(
    extensions: &[(Value, Value)],
) -> Result<Option<TransitionDetails>, VerifyError> {
    let custody = map_lookup_optional_value(extensions, "trellis.custody-model-transition.v1");
    let disclosure =
        map_lookup_optional_value(extensions, "trellis.disclosure-profile-transition.v1");
    if custody.is_some() && disclosure.is_some() {
        return Err(VerifyError::new(
            "extensions MUST NOT contain both trellis.custody-model-transition.v1 and trellis.disclosure-profile-transition.v1 on the same event",
        ));
    }
    if let Some(extension_value) = custody {
        return Ok(Some(decode_custody_model_transition(extension_value)?));
    }
    if let Some(extension_value) = disclosure {
        return Ok(Some(decode_disclosure_profile_transition(extension_value)?));
    }
    Ok(None)
}

pub(crate) fn decode_custody_model_transition(
    extension_value: &Value,
) -> Result<TransitionDetails, VerifyError> {
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("custody-model transition extension is not a map"))?;
    let transition_id = map_lookup_text(extension_map, "transition_id")?;
    let from_state = map_lookup_text(extension_map, "from_custody_model")?;
    let to_state = map_lookup_text(extension_map, "to_custody_model")?;
    let _effective_at = map_lookup_timestamp(extension_map, "effective_at")?;
    let declaration_digest = bytes_array(&map_lookup_fixed_bytes(
        extension_map,
        "declaration_doc_digest",
        32,
    )?);
    let attestation_classes = decode_attestation_classes(extension_map)?;

    Ok(TransitionDetails {
        kind: TransitionKind::CustodyModel,
        transition_id,
        from_state,
        to_state,
        declaration_digest,
        attestation_classes,
        scope_change: None,
    })
}

pub(crate) fn decode_disclosure_profile_transition(
    extension_value: &Value,
) -> Result<TransitionDetails, VerifyError> {
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("disclosure-profile transition extension is not a map"))?;
    let transition_id = map_lookup_text(extension_map, "transition_id")?;
    let from_state = map_lookup_text(extension_map, "from_disclosure_profile")?;
    let to_state = map_lookup_text(extension_map, "to_disclosure_profile")?;
    let _effective_at = map_lookup_timestamp(extension_map, "effective_at")?;
    let declaration_digest = bytes_array(&map_lookup_fixed_bytes(
        extension_map,
        "declaration_doc_digest",
        32,
    )?);
    let scope_change = map_lookup_text(extension_map, "scope_change")?;
    let attestation_classes = decode_attestation_classes(extension_map)?;

    Ok(TransitionDetails {
        kind: TransitionKind::DisclosureProfile,
        transition_id,
        from_state,
        to_state,
        declaration_digest,
        attestation_classes,
        scope_change: Some(scope_change),
    })
}

pub(crate) fn decode_attestation_classes(
    extension_map: &[(Value, Value)],
) -> Result<Vec<String>, VerifyError> {
    let attestations = map_lookup_array(extension_map, "attestations")?;
    Ok(attestations
        .iter()
        .filter_map(|item| item.as_map())
        .filter_map(|map| map_lookup_text(map, "authority_class").ok())
        .collect())
}

pub(crate) fn decode_attachment_binding_details(
    extensions: &[(Value, Value)],
) -> Result<Option<AttachmentBindingDetails>, VerifyError> {
    let Some(extension_value) = map_lookup_optional_value(extensions, ATTACHMENT_EVENT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("attachment binding extension is not a map"))?;
    let attachment_id = map_lookup_text(extension_map, "attachment_id")?;
    let slot_path = map_lookup_text(extension_map, "slot_path")?;
    let media_type = map_lookup_text(extension_map, "media_type")?;
    let byte_length = map_lookup_u64(extension_map, "byte_length")?;
    let attachment_sha256 =
        parse_sha256_text(&map_lookup_text(extension_map, "attachment_sha256")?)?;
    let payload_content_hash =
        parse_sha256_text(&map_lookup_text(extension_map, "payload_content_hash")?)?;
    let filename = map_lookup_optional_text(extension_map, "filename")?;
    let prior_binding_hash = match map_lookup_optional_value(extension_map, "prior_binding_hash") {
        Some(Value::Text(value)) => Some(parse_sha256_text(value)?),
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(VerifyError::new(
                "attachment binding prior_binding_hash is neither sha256 text nor null",
            ));
        }
    };

    Ok(Some(AttachmentBindingDetails {
        attachment_id,
        slot_path,
        media_type,
        byte_length,
        attachment_sha256,
        payload_content_hash,
        filename,
        prior_binding_hash,
    }))
}

/// Decodes the optional `trellis.erasure-evidence.v1` extension payload
/// and runs ADR 0005 §"Verifier obligations" steps 1 (CDDL), 3 (subject_scope
/// shape), and 6 (hsm_receipt null-consistency) inline. Step 4 (`destroyed_at`
/// vs hosting event `authored_at`) is also enforced here because both inputs
/// are local to one event. Steps 2 / 5 / 7 / 8 / 9 / 10 run in the cross-event
/// finalization pass after every event has been decoded.
///
/// `host_authored_at` is the `authored_at` of the carrying event so step 4
/// can short-circuit at decode time.
pub(crate) fn decode_erasure_evidence_details(
    extensions: &[(Value, Value)],
    host_authored_at: TrellisTimestamp,
) -> Result<Option<ErasureEvidenceDetails>, VerifyError> {
    let Some(extension_value) =
        map_lookup_optional_value(extensions, ERASURE_EVIDENCE_EVENT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("erasure-evidence extension is not a map"))?;

    // Step 1: CDDL decode. Required fields per ADR 0005 §"Wire shape".
    let evidence_id = map_lookup_text(extension_map, "evidence_id")?;
    let kid_destroyed = map_lookup_fixed_bytes(extension_map, "kid_destroyed", 16)?;

    // Step 2 prep: capture `key_class` and apply the `wrap` → `subject`
    // normalization at decode time so cross-event step 5 / step 8 reasoning
    // operates on the canonical taxonomy. Registry-bind happens in the
    // finalize pass once the registry maps are in scope.
    let wire_key_class = map_lookup_text(extension_map, "key_class")?;
    let norm_key_class = if wire_key_class == "wrap" {
        "subject".to_string()
    } else {
        wire_key_class
    };

    let destroyed_at = map_lookup_timestamp(extension_map, "destroyed_at")?;

    // Step 4: `destroyed_at` MUST be ≤ host event's `authored_at`.
    // Companion OC-144 / TR-OP-109. Violation is a structure failure with
    // typed kind so the report's `tamper_kind` carries
    // `erasure_destroyed_at_after_host`.
    if destroyed_at > host_authored_at {
        return Err(VerifyError::with_kind(
            format!(
                "erasure-evidence `destroyed_at` ({destroyed_at}) exceeds hosting event `authored_at` ({host_authored_at}) (Companion OC-144 / ADR 0005 step 4)"
            ),
            VerifyErrorKind::ErasureDestroyedAtAfterHost,
        ));
    }

    // CDDL: cascade_scopes is a non-empty array of CascadeScope text strings.
    let cascade_array = map_lookup_array(extension_map, "cascade_scopes")?;
    if cascade_array.is_empty() {
        return Err(VerifyError::new(
            "erasure-evidence `cascade_scopes` MUST be a non-empty array (ADR 0005 §Wire shape)",
        ));
    }
    let mut cascade_scopes = Vec::with_capacity(cascade_array.len());
    for scope_value in cascade_array {
        let scope = scope_value
            .as_text()
            .ok_or_else(|| VerifyError::new("erasure-evidence cascade_scope entry is not text"))?;
        cascade_scopes.push(scope.to_string());
    }

    let completion_mode = map_lookup_text(extension_map, "completion_mode")?;
    let _destruction_actor = map_lookup_text(extension_map, "destruction_actor")?;
    let _policy_authority = map_lookup_text(extension_map, "policy_authority")?;
    let _reason_code = map_lookup_u64(extension_map, "reason_code")?;

    // Step 3: `subject_scope` cross-field shape by `kind`.
    let subject_scope_value = map_lookup_optional_value(extension_map, "subject_scope")
        .ok_or_else(|| VerifyError::new("erasure-evidence `subject_scope` is missing"))?;
    let subject_scope_map = subject_scope_value
        .as_map()
        .ok_or_else(|| VerifyError::new("erasure-evidence `subject_scope` is not a map"))?;
    let subject_scope_kind = map_lookup_text(subject_scope_map, "kind")?;
    validate_subject_scope_shape(subject_scope_map, &subject_scope_kind)?;

    // Step 6: `hsm_receipt` / `hsm_receipt_kind` null-consistency.
    let receipt_present = matches!(
        map_lookup_optional_value(extension_map, "hsm_receipt"),
        Some(Value::Bytes(_))
    );
    let receipt_kind_present = matches!(
        map_lookup_optional_value(extension_map, "hsm_receipt_kind"),
        Some(Value::Text(_))
    );
    if receipt_present != receipt_kind_present {
        return Err(VerifyError::new(
            "erasure-evidence `hsm_receipt` and `hsm_receipt_kind` must both be null or both non-null (ADR 0005 step 6)",
        ));
    }

    // Step 7 (Phase-1 structural): every attestation row carries a 64-byte
    // signature and a recognized `authority_class`. Crypto-verification of
    // the Ed25519 signature itself rides Phase-2+ — same posture as the
    // existing `decode_attestation_classes` flow for posture transitions.
    let attestations = map_lookup_array(extension_map, "attestations")?;
    if attestations.is_empty() {
        return Err(VerifyError::new(
            "erasure-evidence `attestations` MUST be non-empty (ADR 0005 §Wire shape)",
        ));
    }
    let mut attestation_classes = Vec::with_capacity(attestations.len());
    let mut attestation_signatures_well_formed = true;
    for entry in attestations {
        let entry_map = entry
            .as_map()
            .ok_or_else(|| VerifyError::new("attestation entry is not a map"))?;
        let class = map_lookup_text(entry_map, "authority_class")?;
        attestation_classes.push(class);
        let signature = map_lookup_bytes(entry_map, "signature")?;
        if signature.len() != 64 {
            attestation_signatures_well_formed = false;
        }
        // `authority` is captured by ADR 0005 wire but not yet used by the
        // Phase-1 verifier (no authority↔key registry binding); we still
        // require the field to exist per CDDL.
        let _authority = map_lookup_text(entry_map, "authority")?;
    }

    Ok(Some(ErasureEvidenceDetails {
        evidence_id,
        kid_destroyed,
        norm_key_class,
        destroyed_at,
        cascade_scopes,
        completion_mode,
        attestation_signatures_well_formed,
        attestation_classes,
        subject_scope_kind,
    }))
}

/// Decodes the optional `trellis.certificate-of-completion.v1` extension
/// payload and runs ADR 0007 §"Verifier obligations" step 1 (CDDL decode +
/// per-event chain-summary invariants) inline. Cross-event steps 2 (id
/// collision), 4 (attachment lineage), 5 (signing-event resolution),
/// 6 (timestamp equivalence), 7 (response_ref equivalence) run in
/// [`finalize_certificates_of_completion`] after every event has been decoded.
///
/// Per-event invariants enforced here:
/// - `signer_count == len(signing_events)` (ADR 0007 §"Verifier obligations"
///   step 2 first clause; `certificate_chain_summary_mismatch`)
/// - `len(signer_display) == len(signing_events)` (same step; same kind)
/// - HTML media type carries non-null `template_hash` (ADR 0007 §"Wire shape"
///   `PresentationArtifact.template_hash`; emitted as a structure failure via
///   the generic `malformed_cose` kind because §19.1 has no dedicated
///   tamper_kind for this case)
pub(crate) fn decode_certificate_payload(
    extensions: &[(Value, Value)],
) -> Result<Option<CertificateDetails>, VerifyError> {
    let Some(extension_value) = map_lookup_optional_value(extensions, CERTIFICATE_EVENT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("certificate-of-completion extension is not a map"))?;

    let certificate_id = map_lookup_text(extension_map, "certificate_id")?;
    let case_ref = map_lookup_optional_text(extension_map, "case_ref")?;
    let completed_at = map_lookup_timestamp(extension_map, "completed_at")?;

    // PresentationArtifact decode.
    let pa_value = map_lookup_optional_value(extension_map, "presentation_artifact")
        .ok_or_else(|| VerifyError::new("certificate `presentation_artifact` is missing"))?;
    let pa_map = pa_value
        .as_map()
        .ok_or_else(|| VerifyError::new("certificate `presentation_artifact` is not a map"))?;
    let pa_content_hash = bytes_array(&map_lookup_fixed_bytes(pa_map, "content_hash", 32)?);
    let pa_media_type = map_lookup_text(pa_map, "media_type")?;
    let pa_byte_length = map_lookup_u64(pa_map, "byte_length")?;
    let pa_attachment_id = map_lookup_text(pa_map, "attachment_id")?;
    let pa_template_id = map_lookup_optional_text(pa_map, "template_id")?;
    let pa_template_hash = map_lookup_optional_fixed_bytes(pa_map, "template_hash", 32)?
        .map(|bytes| bytes_array(&bytes));
    // ADR 0007 §"Wire shape" `PresentationArtifact.template_hash`: when
    // `media_type = "text/html"`, `template_hash` MUST be non-null even when
    // `template_id` is null. §19.1 has no dedicated tamper_kind for this
    // case; surface as a generic structure failure via `malformed_cose`
    // (consistent with other CDDL-shape failures at decode time).
    if pa_media_type == "text/html" && pa_template_hash.is_none() {
        return Err(VerifyError::with_kind(
            "certificate presentation_artifact: media_type=text/html requires template_hash to be non-null (ADR 0007 §Wire shape)",
            VerifyErrorKind::MalformedCose,
        ));
    }

    // ChainSummary decode + per-event invariants.
    let cs_value = map_lookup_optional_value(extension_map, "chain_summary")
        .ok_or_else(|| VerifyError::new("certificate `chain_summary` is missing"))?;
    let cs_map = cs_value
        .as_map()
        .ok_or_else(|| VerifyError::new("certificate `chain_summary` is not a map"))?;
    let signer_count = map_lookup_u64(cs_map, "signer_count")?;
    let signer_display_array = map_lookup_array(cs_map, "signer_display")?;
    if signer_display_array.is_empty() {
        return Err(VerifyError::new(
            "certificate `chain_summary.signer_display` MUST be non-empty (ADR 0007 §Wire shape)",
        ));
    }
    let mut signer_display = Vec::with_capacity(signer_display_array.len());
    for entry in signer_display_array {
        let entry_map = entry
            .as_map()
            .ok_or_else(|| VerifyError::new("signer_display entry is not a map"))?;
        let principal_ref = map_lookup_text(entry_map, "principal_ref")?;
        let display_name = map_lookup_text(entry_map, "display_name")?;
        let display_role = map_lookup_optional_text(entry_map, "display_role")?;
        let signed_at = map_lookup_timestamp(entry_map, "signed_at")?;
        signer_display.push(SignerDisplayDetails {
            principal_ref,
            display_name,
            display_role,
            signed_at,
        });
    }
    let response_ref = map_lookup_optional_fixed_bytes(cs_map, "response_ref", 32)?
        .map(|bytes| bytes_array(&bytes));
    let workflow_status = map_lookup_text(cs_map, "workflow_status")?;
    let impact_level = map_lookup_optional_text(cs_map, "impact_level")?;
    let covered_claims_value = map_lookup_optional_value(cs_map, "covered_claims");
    let covered_claims = match covered_claims_value {
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let tag = item.as_text().ok_or_else(|| {
                    VerifyError::new("certificate covered_claims entry is not text")
                })?;
                out.push(tag.to_string());
            }
            out
        }
        Some(Value::Null) | None => Vec::new(),
        Some(_) => {
            return Err(VerifyError::new(
                "certificate `chain_summary.covered_claims` is not an array",
            ));
        }
    };

    // signing_events decode.
    let signing_events_array = map_lookup_array(extension_map, "signing_events")?;
    if signing_events_array.is_empty() {
        return Err(VerifyError::new(
            "certificate `signing_events` MUST be non-empty (ADR 0007 §Wire shape)",
        ));
    }
    let mut signing_events = Vec::with_capacity(signing_events_array.len());
    for digest_value in signing_events_array {
        let bytes = digest_value
            .as_bytes()
            .ok_or_else(|| VerifyError::new("signing_events entry is not a byte string"))?;
        let digest: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::new("signing_events entry is not 32 bytes"))?;
        signing_events.push(digest);
    }

    // ADR 0007 §"Verifier obligations" step 2 first invariant: per-event
    // shape (signer_count == len(signing_events) AND len(signer_display) ==
    // len(signing_events)). Mismatch flips integrity via the
    // `certificate_chain_summary_mismatch` tamper_kind.
    if signer_count as usize != signing_events.len() || signer_display.len() != signing_events.len()
    {
        return Err(VerifyError::with_kind(
            format!(
                "certificate chain_summary invariant violated: signer_count={}, signing_events={}, signer_display={} (ADR 0007 §Verifier obligations step 2)",
                signer_count,
                signing_events.len(),
                signer_display.len()
            ),
            VerifyErrorKind::CertificateChainSummaryMismatch,
        ));
    }

    let workflow_ref = map_lookup_optional_text(extension_map, "workflow_ref")?;

    // Step 3 (Phase-1 structural): every attestation row carries a 64-byte
    // signature and a recognized `authority_class`. Crypto-verification of
    // the Ed25519 signature itself rides Phase-2+ — same posture as the
    // existing posture-transition + erasure flows.
    let attestations = map_lookup_array(extension_map, "attestations")?;
    if attestations.is_empty() {
        return Err(VerifyError::new(
            "certificate `attestations` MUST be non-empty (ADR 0007 §Wire shape)",
        ));
    }
    let mut attestation_signatures_well_formed = true;
    for entry in attestations {
        let entry_map = entry
            .as_map()
            .ok_or_else(|| VerifyError::new("attestation entry is not a map"))?;
        let _class = map_lookup_text(entry_map, "authority_class")?;
        let signature = map_lookup_bytes(entry_map, "signature")?;
        if signature.len() != 64 {
            attestation_signatures_well_formed = false;
        }
        let _authority = map_lookup_text(entry_map, "authority")?;
    }

    Ok(Some(CertificateDetails {
        certificate_id,
        case_ref,
        completed_at,
        presentation_artifact: PresentationArtifactDetails {
            content_hash: pa_content_hash,
            media_type: pa_media_type,
            byte_length: pa_byte_length,
            attachment_id: pa_attachment_id,
            template_id: pa_template_id,
            template_hash: pa_template_hash,
        },
        chain_summary: ChainSummaryDetails {
            signer_count,
            signer_display,
            response_ref,
            workflow_status,
            impact_level,
            covered_claims,
        },
        signing_events,
        workflow_ref,
        attestation_signatures_well_formed,
    }))
}

/// Decodes the optional `trellis.user-content-attestation.v1` extension
/// payload and runs ADR 0010 §"Verifier obligations" step 1 (CDDL decode)
/// and step 2 partial (`signing_intent` URI well-formedness;
/// `attested_at == envelope.authored_at` exact equality) inline. Cross-event
/// steps 3 (chain-position resolution), 4 (identity resolution),
/// 5 (signature verification), 6 (key-state check), 7 (collision detection),
/// 8 (operator-in-user-slot enforcement), and 9 (outcome accumulation) run
/// in [`finalize_user_content_attestations`] after every event has been
/// decoded.
///
/// Per-event invariants enforced here:
/// - `attested_at == host EventHeader.authored_at` (timestamp exact equality;
///   `user_content_attestation_timestamp_mismatch`)
/// - `signing_intent` is a syntactically valid URI per RFC 3986
///   (`user_content_attestation_intent_malformed`)
/// - structural CDDL shape per Core §28 / ADR 0010 §"Wire shape"
pub(crate) fn decode_user_content_attestation_payload(
    extensions: &[(Value, Value)],
    host_authored_at: TrellisTimestamp,
) -> Result<Option<UserContentAttestationDetails>, VerifyError> {
    let Some(extension_value) =
        map_lookup_optional_value(extensions, USER_CONTENT_ATTESTATION_EVENT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("user-content-attestation extension is not a map"))?;

    let attestation_id = map_lookup_text(extension_map, "attestation_id")?;
    let attested_event_hash = bytes_array(&map_lookup_fixed_bytes(
        extension_map,
        "attested_event_hash",
        32,
    )?);
    let attested_event_position = map_lookup_u64(extension_map, "attested_event_position")?;
    let attestor = map_lookup_text(extension_map, "attestor")?;
    let identity_attestation_ref =
        map_lookup_optional_fixed_bytes(extension_map, "identity_attestation_ref", 32)?
            .map(|bytes| bytes_array(&bytes));
    let signing_intent = map_lookup_text(extension_map, "signing_intent")?;
    let attested_at = map_lookup_timestamp(extension_map, "attested_at")?;
    let signature_bytes = map_lookup_fixed_bytes(extension_map, "signature", 64)?;
    let signature: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::new("user-content-attestation signature is not 64 bytes"))?;
    let signing_kid = map_lookup_fixed_bytes(extension_map, "signing_kid", 16)?;

    // Step 2 partial — `attested_at` MUST exactly equal envelope `authored_at`
    // (timestamp exact equality; no skew slack per ADR 0010 §"Field semantics"
    // `attested_at` clause).
    // Step 2 — intra-payload invariants. Per ADR 0010 §"Verifier obligations"
    // step 2, these flip `integrity_verified = false` only — they are NOT
    // structure failures, so the deferred-failure marker rides through to
    // finalize where it surfaces as an `event_failure`. Returning `Err` here
    // would (incorrectly) flip `readability_verified = false` per the
    // `verify_tampered_ledger` fatal-decode path. First-detected wins;
    // additional invariants land via the same marker pattern if the corpus
    // grows.
    let step_2_failure: Option<VerificationFailureKind> = if attested_at != host_authored_at {
        Some(VerificationFailureKind::UserContentAttestationTimestampMismatch)
    } else if !is_syntactically_valid_uri(&signing_intent) {
        Some(VerificationFailureKind::UserContentAttestationIntentMalformed)
    } else {
        None
    };

    let canonical_preimage = compute_user_content_attestation_preimage(
        &attestation_id,
        &attested_event_hash,
        attested_event_position,
        &attestor,
        identity_attestation_ref.as_ref(),
        &signing_intent,
        attested_at,
    );

    Ok(Some(UserContentAttestationDetails {
        attestation_id,
        attested_event_hash,
        attested_event_position,
        attestor,
        identity_attestation_ref,
        signing_intent,
        attested_at,
        signature,
        signing_kid,
        canonical_preimage,
        step_2_failure,
    }))
}

/// Builds the dCBOR signature preimage for a user-content attestation per
/// ADR 0010 §"Wire shape": `dCBOR([attestation_id, attested_event_hash,
/// attested_event_position, attestor, identity_attestation_ref,
/// signing_intent, attested_at])`. Pre-computed at decode time so the
/// finalize pass can re-verify without re-encoding. The encoded array is
/// then domain-separated under `trellis-user-content-attestation-v1`
/// (Core §9.8) inside [`verify_user_content_attestation_signature`].
pub(crate) fn compute_user_content_attestation_preimage(
    attestation_id: &str,
    attested_event_hash: &[u8; 32],
    attested_event_position: u64,
    attestor: &str,
    identity_attestation_ref: Option<&[u8; 32]>,
    signing_intent: &str,
    attested_at: TrellisTimestamp,
) -> Vec<u8> {
    let identity_value = match identity_attestation_ref {
        Some(digest) => Value::Bytes(digest.to_vec()),
        None => Value::Null,
    };
    let timestamp_value = Value::Array(vec![
        Value::Integer(attested_at.seconds.into()),
        Value::Integer(attested_at.nanos.into()),
    ]);
    let array = Value::Array(vec![
        Value::Text(attestation_id.to_owned()),
        Value::Bytes(attested_event_hash.to_vec()),
        Value::Integer(attested_event_position.into()),
        Value::Text(attestor.to_owned()),
        identity_value,
        Value::Text(signing_intent.to_owned()),
        timestamp_value,
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&array, &mut buf)
        .expect("ciborium serialization to a Vec cannot fail");
    buf
}

pub(crate) fn parse_attachment_export_extension(
    manifest_map: &[(Value, Value)],
) -> Result<Option<AttachmentExportExtension>, VerifyError> {
    let Some(extensions) = map_lookup_optional_map(manifest_map, "extensions")? else {
        return Ok(None);
    };
    let Some(extension_value) = map_lookup_optional_value(extensions, ATTACHMENT_EXPORT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("attachment export extension is not a map"))?;
    Ok(Some(AttachmentExportExtension {
        manifest_digest: bytes_array(&map_lookup_fixed_bytes(
            extension_map,
            "attachment_manifest_digest",
            32,
        )?),
        inline_attachments: map_lookup_bool(extension_map, "inline_attachments")?,
    }))
}

/// Parses the optional `trellis.export.certificates-of-completion.v1`
/// manifest extension (ADR 0007 §"Export manifest catalog"). Mirror of
/// [`parse_erasure_evidence_export_extension`].
pub(crate) fn parse_certificate_export_extension(
    manifest_map: &[(Value, Value)],
) -> Result<Option<CertificateExportExtension>, VerifyError> {
    let Some(extensions) = map_lookup_optional_map(manifest_map, "extensions")? else {
        return Ok(None);
    };
    let Some(extension_value) = map_lookup_optional_value(extensions, CERTIFICATE_EXPORT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("certificate export extension is not a map"))?;
    let catalog_ref = map_lookup_text(extension_map, "catalog_ref")?;
    if !catalog_ref.is_ascii() {
        return Err(VerifyError::new(
            "certificate export extension catalog_ref must be ASCII (ZIP member path)",
        ));
    }
    Ok(Some(CertificateExportExtension {
        catalog_ref,
        catalog_digest: bytes_array(&map_lookup_fixed_bytes(
            extension_map,
            "catalog_digest",
            32,
        )?),
        entry_count: map_lookup_u64(extension_map, "entry_count")?,
    }))
}

pub(crate) fn parse_erasure_evidence_export_extension(
    manifest_map: &[(Value, Value)],
) -> Result<Option<ErasureEvidenceExportExtension>, VerifyError> {
    let Some(extensions) = map_lookup_optional_map(manifest_map, "extensions")? else {
        return Ok(None);
    };
    let Some(extension_value) =
        map_lookup_optional_value(extensions, ERASURE_EVIDENCE_EXPORT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("erasure export extension is not a map"))?;
    let catalog_ref = map_lookup_text(extension_map, "catalog_ref")?;
    if !catalog_ref.is_ascii() {
        return Err(VerifyError::new(
            "erasure export extension catalog_ref must be ASCII (ZIP member path)",
        ));
    }
    Ok(Some(ErasureEvidenceExportExtension {
        catalog_ref,
        catalog_digest: bytes_array(&map_lookup_fixed_bytes(
            extension_map,
            "catalog_digest",
            32,
        )?),
        entry_count: map_lookup_u64(extension_map, "entry_count")?,
    }))
}

pub(crate) fn parse_supersession_graph_export_extension(
    manifest_map: &[(Value, Value)],
) -> Result<Option<SupersessionGraphExportExtension>, VerifyError> {
    let Some(extensions) = map_lookup_optional_map(manifest_map, "extensions")? else {
        return Ok(None);
    };
    let Some(extension_value) =
        map_lookup_optional_value(extensions, SUPERSESSION_GRAPH_EXPORT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("supersession graph export extension is not a map"))?;
    Ok(Some(SupersessionGraphExportExtension {
        graph_digest: bytes_array(&map_lookup_fixed_bytes(extension_map, "graph_digest", 32)?),
        predecessor_count: map_lookup_u64(extension_map, "predecessor_count")?,
    }))
}

pub(crate) fn parse_open_clocks_export_extension(
    manifest_map: &[(Value, Value)],
) -> Result<Option<OpenClocksExportExtension>, VerifyError> {
    let Some(extensions) = map_lookup_optional_map(manifest_map, "extensions")? else {
        return Ok(None);
    };
    let Some(extension_value) = map_lookup_optional_value(extensions, OPEN_CLOCKS_EXPORT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("open clocks export extension is not a map"))?;
    Ok(Some(OpenClocksExportExtension {
        open_clocks_digest: bytes_array(&map_lookup_fixed_bytes(
            extension_map,
            "open_clocks_digest",
            32,
        )?),
        open_clock_count: map_lookup_u64(extension_map, "open_clock_count")?,
    }))
}

pub(crate) fn parse_seal_fence_export_extension(
    manifest_map: &[(Value, Value)],
) -> Result<Option<SealFenceExportExtension>, VerifyError> {
    let Some(extensions) = map_lookup_optional_map(manifest_map, "extensions")? else {
        return Ok(None);
    };
    let Some(extension_value) = map_lookup_optional_value(extensions, SEAL_FENCE_EXPORT_EXTENSION)
    else {
        return Ok(None);
    };
    let extension_map = extension_value
        .as_map()
        .ok_or_else(|| VerifyError::new("seal fence export extension is not a map"))?;
    let identity_rule = map_lookup_text(extension_map, "identity_rule")?;
    if identity_rule != "trellis-export-seal-fence-v1" {
        return Err(VerifyError::new(
            "seal fence export extension identity_rule is unsupported",
        ));
    }
    let policy_closure_digest = match map_lookup_optional_value(
        extension_map,
        "policy_closure_digest",
    ) {
        Some(Value::Null) => None,
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => Some(bytes_array(bytes)),
        Some(_) => {
            return Err(VerifyError::new(
                "seal fence export extension policy_closure_digest must be null or bstr .size 32",
            ));
        }
        None => {
            return Err(VerifyError::new(
                "seal fence export extension policy_closure_digest is required",
            ));
        }
    };
    Ok(Some(SealFenceExportExtension {
        bundle_scope: map_lookup_bytes(extension_map, "bundle_scope")?,
        export_attempt_id: map_lookup_text(extension_map, "export_attempt_id")?,
        seal_version: map_lookup_u64(extension_map, "seal_version")?,
        event_count: map_lookup_u64(extension_map, "event_count")?,
        high_water_sequence: map_lookup_u64(extension_map, "high_water_sequence")?,
        head_checkpoint_digest: bytes_array(&map_lookup_fixed_bytes(
            extension_map,
            "head_checkpoint_digest",
            32,
        )?),
        events_digest: bytes_array(&map_lookup_fixed_bytes(extension_map, "events_digest", 32)?),
        policy_closure_digest,
    }))
}

pub(crate) fn parse_erasure_catalog_entries(
    catalog_bytes: &[u8],
) -> Result<Vec<ErasureEvidenceCatalogEntryRow>, VerifyError> {
    let value = decode_value(catalog_bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| VerifyError::new("erasure evidence catalog root is not an array"))?;
    entries
        .iter()
        .map(|entry| {
            let map = entry
                .as_map()
                .ok_or_else(|| VerifyError::new("erasure evidence catalog entry is not a map"))?;
            let cascade_array = map_lookup_array(map, "cascade_scopes")?;
            if cascade_array.is_empty() {
                return Err(VerifyError::new(
                    "erasure evidence catalog cascade_scopes MUST be non-empty",
                ));
            }
            let mut cascade_scopes = Vec::with_capacity(cascade_array.len());
            for scope_value in cascade_array {
                let scope = scope_value.as_text().ok_or_else(|| {
                    VerifyError::new("erasure catalog cascade_scope entry is not text")
                })?;
                cascade_scopes.push(scope.to_string());
            }
            let kid_bytes = map_lookup_fixed_bytes(map, "kid_destroyed", 16)?;
            let kid_destroyed: [u8; 16] = kid_bytes
                .as_slice()
                .try_into()
                .expect("map_lookup_fixed_bytes enforces 16-byte kid_destroyed");
            Ok(ErasureEvidenceCatalogEntryRow {
                canonical_event_hash: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "canonical_event_hash",
                    32,
                )?),
                evidence_id: map_lookup_text(map, "evidence_id")?,
                kid_destroyed,
                destroyed_at: map_lookup_timestamp(map, "destroyed_at")?,
                completion_mode: map_lookup_text(map, "completion_mode")?,
                cascade_scopes,
                subject_scope_kind: map_lookup_text(map, "subject_scope_kind")?,
            })
        })
        .collect()
}

/// Decodes `065-certificates-of-completion.cbor` (ADR 0007 §"Export manifest
/// catalog" — `CertificateOfCompletionCatalogEntry`). Mirror of
/// [`parse_erasure_catalog_entries`].
pub(crate) fn parse_certificate_catalog_entries(
    catalog_bytes: &[u8],
) -> Result<Vec<CertificateCatalogEntryRow>, VerifyError> {
    let value = decode_value(catalog_bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| VerifyError::new("certificate catalog root is not an array"))?;
    entries
        .iter()
        .map(|entry| {
            let map = entry
                .as_map()
                .ok_or_else(|| VerifyError::new("certificate catalog entry is not a map"))?;
            Ok(CertificateCatalogEntryRow {
                canonical_event_hash: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "canonical_event_hash",
                    32,
                )?),
                certificate_id: map_lookup_text(map, "certificate_id")?,
                completed_at: map_lookup_timestamp(map, "completed_at")?,
                signer_count: map_lookup_u64(map, "signer_count")?,
                media_type: map_lookup_text(map, "media_type")?,
                attachment_id: map_lookup_text(map, "attachment_id")?,
                workflow_status: map_lookup_text(map, "workflow_status")?,
            })
        })
        .collect()
}

pub(crate) fn parse_attachment_manifest_entries(
    manifest_bytes: &[u8],
) -> Result<Vec<AttachmentManifestEntry>, VerifyError> {
    let value = decode_value(manifest_bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| VerifyError::new("attachment manifest root is not an array"))?;
    entries
        .iter()
        .map(|entry| {
            let map = entry
                .as_map()
                .ok_or_else(|| VerifyError::new("attachment manifest entry is not a map"))?;
            Ok(AttachmentManifestEntry {
                binding_event_hash: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "binding_event_hash",
                    32,
                )?),
                attachment_id: map_lookup_text(map, "attachment_id")?,
                slot_path: map_lookup_text(map, "slot_path")?,
                media_type: map_lookup_text(map, "media_type")?,
                byte_length: map_lookup_u64(map, "byte_length")?,
                attachment_sha256: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "attachment_sha256",
                    32,
                )?),
                payload_content_hash: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "payload_content_hash",
                    32,
                )?),
                filename: map_lookup_optional_text(map, "filename")?,
                prior_binding_hash: map_lookup_optional_fixed_bytes(map, "prior_binding_hash", 32)?
                    .map(|bytes| bytes_array(&bytes)),
            })
        })
        .collect()
}

pub(crate) fn readable_payload_bytes(
    details: &EventDetails,
    payload_blobs: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Option<Vec<u8>> {
    match &details.payload_ref {
        PayloadRef::Inline(bytes) => Some(bytes.clone()),
        PayloadRef::External => payload_blobs.get(&details.content_hash).cloned(),
    }
}

/// Parses the unified key registry per Core §8 (ADR 0006).
///
/// Verifier dispatch follows Core §8.7.3 step 1: an entry whose top-level map
/// carries a `kind` field is `KeyEntry` (§8.7.1); an entry without `kind` is
/// the legacy `SigningKeyEntry` flat shape (§8.2). Both paths populate the
/// signing-key map identically for `kind = "signing"` and the legacy shape.
///
/// Reserved non-signing classes (`tenant-root`, `scope`, `subject`,
/// `recovery`) and unknown extension `tstr` kinds are NOT inserted into the
/// signing-key map — they cannot resolve a COSE_Sign1 protected-header `kid`.
/// They are returned in `non_signing` so the caller can emit
/// `key_class_mismatch` (Core §8.7.3 step 4) when an event tries to sign under
/// such a kid, distinct from the generic `unresolvable_manifest_kid` failure.
///
/// Per Core §8.7.6 the wire string `"wrap"` is a deprecated synonym for
/// `"subject"`; this parser normalizes the stored class label so callers see
/// only the canonical taxonomy.
#[cfg(test)]
#[expect(
    dead_code,
    reason = "retained for downstream Trellis verifier test fixtures"
)]
pub(crate) fn parse_signing_key_registry(
    bytes: &[u8],
) -> Result<BTreeMap<Vec<u8>, SigningKeyEntry>, VerifyError> {
    let (signing, _non_signing) = parse_key_registry(bytes)?;
    Ok(signing)
}

#[allow(clippy::type_complexity)]
pub(crate) fn parse_key_registry(
    bytes: &[u8],
) -> Result<
    (
        BTreeMap<Vec<u8>, SigningKeyEntry>,
        BTreeMap<Vec<u8>, NonSigningKeyEntry>,
    ),
    VerifyError,
> {
    let value = decode_value(bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| VerifyError::new("signing-key registry root is not an array"))?;
    let mut registry = BTreeMap::new();
    let mut non_signing = BTreeMap::new();
    for entry in entries {
        let map = entry
            .as_map()
            .ok_or_else(|| VerifyError::new("signing-key registry entry is not a map"))?;

        // Core §8.7.3 step 1: dispatch on presence of the top-level `kind`
        // field. Absent → legacy `SigningKeyEntry` (§8.2); present →
        // `KeyEntry` (§8.7.1) with `kind` discriminating the arm.
        let kind = map_lookup_optional_text(map, "kind")?;
        let kind_norm = kind.as_deref().map(|s| match s {
            // Core §8.7.6: `"wrap"` is a deprecated synonym for `"subject"`.
            "wrap" => "subject",
            other => other,
        });

        let kid = map_lookup_bytes(map, "kid")?;

        match kind_norm {
            // Legacy `SigningKeyEntry` (no `kind` field) OR new `KeyEntrySigning`.
            None | Some("signing") => {
                let pubkey = bytes_array(&map_lookup_fixed_bytes(map, "pubkey", 32)?);
                let status = map_lookup_u64(map, "status")?;
                let valid_from: Option<TrellisTimestamp> = match map_lookup_optional_value(
                    map,
                    "valid_from",
                ) {
                    Some(Value::Array(arr)) => Some(decode_timestamp_array(arr)?),
                    Some(Value::Null) | None => None,
                    // `valid_from` was captured-but-unused before rotation
                    // grace. Preserve historical snapshots that encoded it as
                    // epoch seconds; `valid_to` stays strict because it closes
                    // signing authority.
                    Some(Value::Integer(i)) => Some(TrellisTimestamp {
                        seconds: u64::try_from(*i).map_err(|_| {
                            VerifyError::new("signing-key registry valid_from out of u64 range")
                        })?,
                        nanos: 0,
                    }),
                    Some(_) => {
                        return Err(VerifyError::new(
                            "signing-key registry valid_from is neither timestamp array nor null",
                        ));
                    }
                };
                let valid_to: Option<TrellisTimestamp> = match map_lookup_optional_value(
                    map, "valid_to",
                ) {
                    Some(Value::Array(arr)) => Some(decode_timestamp_array(arr)?),
                    Some(Value::Null) | None => None,
                    Some(Value::Integer(_)) => {
                        return Err(VerifyError::with_kind(
                            "signing-key registry valid_to is legacy uint format; expected [seconds, nanos] array per ADR 0069 D-2.1",
                            VerifyErrorKind::LegacyTimestampFormat,
                        ));
                    }
                    Some(_) => {
                        return Err(VerifyError::new(
                            "signing-key registry valid_to is neither timestamp array nor null",
                        ));
                    }
                };
                registry.insert(
                    kid,
                    SigningKeyEntry {
                        public_key: pubkey,
                        status,
                        valid_from,
                        valid_to,
                    },
                );
            }
            // Core §8.7.3 step 3: reserved non-signing class. Phase-1
            // verifier does not validate class-specific inner fields (those
            // slots are envelope reservations and the deep validation rides
            // Phase-2+ activation per ADR 0006), but it DOES enforce the
            // structural-shape gate of §8.7.1: the entry MUST carry an
            // `attributes` map. Absent or wrong-typed `attributes` → fail
            // with `key_entry_attributes_shape_mismatch` (TR-CORE-048).
            //
            // The kind tag on the resulting `VerifyError` is consumed by
            // `verify_export_zip` / `verify_tampered_ledger` so the report's
            // `tamper_kind` field carries the structural-failure code rather
            // than the generic `signing_key_registry_invalid`.
            Some(class) if RESERVED_NON_SIGNING_KIND.contains(&class) => {
                let attributes = map_lookup_optional_value(map, "attributes");
                let attributes_map: Option<&[(Value, Value)]> = match attributes {
                    Some(Value::Map(map)) => Some(map.as_slice()),
                    None => {
                        return Err(VerifyError::with_kind(
                            format!(
                                "key_entry_attributes_shape_mismatch: KeyEntry of \
                                 kind=\"{class}\" missing required `attributes` map (Core §8.7.1)"
                            ),
                            VerifyErrorKind::KeyEntryAttributesShapeMismatch,
                        ));
                    }
                    Some(_) => {
                        return Err(VerifyError::with_kind(
                            format!(
                                "key_entry_attributes_shape_mismatch: KeyEntry of \
                                 kind=\"{class}\" `attributes` is not a map (Core §8.7.1)"
                            ),
                            VerifyErrorKind::KeyEntryAttributesShapeMismatch,
                        ));
                    }
                };

                // Subject-class capture: read `valid_to` from `attributes`
                // for forward-compatible Phase-2+ enforcement; absent or
                // null is the dominant Phase-1 case. Other classes don't
                // carry a `valid_to` field per §8.7.2.
                let subject_valid_to: Option<TrellisTimestamp> = if class == "subject" {
                    let valid_to_field = attributes_map
                        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("valid_to")));
                    match valid_to_field {
                        Some((_, Value::Array(arr))) => Some(decode_timestamp_array(arr)?),
                        Some((_, Value::Null)) | None => None,
                        Some((_, Value::Integer(_))) => {
                            return Err(VerifyError::with_kind(
                                "key_entry_attributes_shape_mismatch: subject \
                                 `valid_to` is legacy uint format; expected [seconds, nanos] array per ADR 0069 D-2.1",
                                VerifyErrorKind::KeyEntryAttributesShapeMismatch,
                            ));
                        }
                        Some(_) => {
                            return Err(VerifyError::with_kind(
                                "key_entry_attributes_shape_mismatch: subject \
                                 `valid_to` is neither timestamp array nor null (Core §8.7.2)",
                                VerifyErrorKind::KeyEntryAttributesShapeMismatch,
                            ));
                        }
                    }
                } else {
                    None
                };

                non_signing.insert(
                    kid,
                    NonSigningKeyEntry {
                        class: class.to_string(),
                        subject_valid_to,
                    },
                );
            }
            // Core §8.7.3 step 4 *Unknown `kind`*: forward-compatibility
            // floor. The entry is admitted at the wire layer; downstream
            // resolution failures (signature attempt under this kid) surface
            // as a capability gap rather than a structure failure here.
            Some(other) => {
                non_signing.insert(
                    kid,
                    NonSigningKeyEntry {
                        class: other.to_string(),
                        subject_valid_to: None,
                    },
                );
            }
        }
    }
    Ok((registry, non_signing))
}

pub(crate) fn parse_bound_registry(bytes: &[u8]) -> Result<BoundRegistry, VerifyError> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| VerifyError::new("bound registry root is not a map"))?;
    let event_types_map = map_lookup_map(map, "event_types")?;
    let mut event_types = Vec::new();
    for (key, _) in event_types_map {
        let name = key
            .as_text()
            .ok_or_else(|| VerifyError::new("event_types key is not text"))?;
        event_types.push(name.to_string());
    }
    let classifications_values = map_lookup_array(map, "classifications")?;
    let classifications = classifications_values
        .iter()
        .map(|value| {
            value
                .as_text()
                .map(|text| text.to_string())
                .ok_or_else(|| VerifyError::new("classification entry is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BoundRegistry {
        event_types,
        classifications,
    })
}

pub(crate) fn parse_custody_model(bytes: &[u8]) -> Result<String, VerifyError> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| VerifyError::new("posture declaration root is not a map"))?;
    let custody_model = map_lookup_map(map, "custody_model")?;
    Ok(map_lookup_text(custody_model, "custody_model_id")?)
}

pub(crate) fn parse_disclosure_profile(bytes: &[u8]) -> Result<String, VerifyError> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| VerifyError::new("posture declaration root is not a map"))?;
    Ok(map_lookup_text(map, "disclosure_profile")?)
}

pub(crate) fn event_identity(event: &ParsedSign1) -> Result<(Vec<u8>, [u8; 32]), VerifyError> {
    let details = decode_event_details(event)?;
    Ok((details.scope, details.canonical_event_hash))
}

pub(crate) fn decode_value(bytes: &[u8]) -> Result<Value, VerifyError> {
    decode_cbor_value(bytes).map_err(Into::into)
}

pub(crate) fn decode_timestamp_array(arr: &[Value]) -> Result<TrellisTimestamp, VerifyError> {
    if arr.len() != 2 {
        return Err(VerifyError::new(
            "timestamp array must have exactly 2 elements",
        ));
    }
    let seconds = match &arr[0] {
        Value::Integer(i) => {
            u64::try_from(*i).map_err(|_| VerifyError::new("timestamp seconds out of u64 range"))?
        }
        _ => return Err(VerifyError::new("timestamp seconds must be uint")),
    };
    let nanos = match &arr[1] {
        Value::Integer(i) => u32::try_from(*i).map_err(|_| {
            VerifyError::with_kind(
                "timestamp nanos must be 0..999999999",
                VerifyErrorKind::TimestampNanosOutOfRange,
            )
        })?,
        _ => return Err(VerifyError::new("timestamp nanos must be uint")),
    };
    if nanos > 999_999_999 {
        return Err(VerifyError::with_kind(
            format!("timestamp nanos must be 0..999999999, got {nanos}"),
            VerifyErrorKind::TimestampNanosOutOfRange,
        ));
    }
    Ok(TrellisTimestamp { seconds, nanos })
}

pub(crate) fn map_lookup_timestamp(
    map: &[(Value, Value)],
    key_name: &str,
) -> Result<TrellisTimestamp, VerifyError> {
    let value = map_lookup_optional_value(map, key_name)
        .ok_or_else(|| VerifyError::new(format!("missing `{key_name}`")))?;
    match value {
        Value::Array(arr) => decode_timestamp_array(arr),
        Value::Integer(_) => Err(VerifyError::with_kind(
            format!(
                "{key_name} is legacy uint format; expected [seconds, nanos] array per ADR 0069 D-2.1"
            ),
            VerifyErrorKind::LegacyTimestampFormat,
        )),
        _ => Err(VerifyError::new(format!(
            "{key_name} must be [uint, uint] array"
        ))),
    }
}
