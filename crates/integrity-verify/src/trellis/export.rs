use std::collections::{BTreeMap, BTreeSet};

use integrity_bundle::read_stored_zip;
use trellis_types::{
    ArtifactType, checkpoint_digest, domain_separated_sha256, encode_canonical_cbor_value,
    map_lookup_array, map_lookup_bytes, map_lookup_fixed_bytes, map_lookup_optional_map,
    map_lookup_u64, sha256_bytes,
};

use super::{
    ALG_EDDSA, SUITE_ID_PHASE_1_I128, attachment_entry_matches_binding,
    verify_event_set_with_classes, verify_signature,
};
use crate::trellis::certificate::{
    verify_certificate_attachment_lineage, verify_certificate_catalog,
};
use crate::trellis::erasure::verify_erasure_evidence_catalog;
use crate::trellis::interop_sidecar::verify_interop_sidecars;
use crate::trellis::kinds::{VerificationFailureKind, VerifyErrorKind};
use crate::trellis::merkle::{
    digest_path_from_values, merkle_leaf_hash, merkle_root, root_from_consistency_proof,
    root_from_inclusion_proof,
};
use crate::trellis::open_clocks::{
    verify_clock_segments, verify_open_clocks, verify_unbound_open_clocks,
};
use crate::trellis::parse::{
    decode_event_details, decode_value, event_identity, map_lookup_timestamp,
    parse_attachment_export_extension, parse_attachment_manifest_entries, parse_bound_registry,
    parse_certificate_export_extension, parse_erasure_evidence_export_extension,
    parse_key_registry, parse_open_clocks_export_extension, parse_seal_fence_export_extension,
    parse_sign1_array, parse_sign1_bytes, parse_supersession_graph_export_extension,
    readable_payload_bytes,
};
use crate::trellis::supersession::{verify_supersession_graph, verify_unbound_supersession_graph};
use crate::trellis::types::*;
use crate::trellis::util::{binding_lineage_graph_has_cycle, bytes_array, hex_decode, hex_string};
use crate::trellis::{
    DomainEvent, DomainExport, EXPORT_ATTEMPT_DOMAIN, RecordValidator, VerificationWithDomain,
};

/// Verifies a complete export ZIP.
pub fn verify_export_zip_with_validator(
    export_zip: &[u8],
    validator: &dyn RecordValidator,
) -> VerificationWithDomain {
    let trellis = verify_export_zip_with_record_validator(export_zip, validator);
    if !trellis.structure_verified {
        return VerificationWithDomain {
            trellis,
            domain_findings: Vec::new(),
        };
    }

    let Ok(domain_export) = parse_domain_export(export_zip) else {
        return VerificationWithDomain {
            trellis,
            domain_findings: Vec::new(),
        };
    };
    let mut domain_findings = validator.validate_events(&domain_export.events);
    domain_findings.extend(validator.validate_export(DomainExport {
        events: &domain_export.events,
        members: &domain_export.members,
        manifest_extensions: &domain_export.manifest_extensions,
    }));
    VerificationWithDomain {
        trellis,
        domain_findings,
    }
}

struct OwnedDomainExport {
    events: Vec<DomainEvent>,
    members: BTreeMap<String, Vec<u8>>,
    manifest_extensions: BTreeMap<String, Vec<u8>>,
}

fn parse_domain_export(export_zip: &[u8]) -> Result<OwnedDomainExport, String> {
    let archive = parse_export_zip(export_zip).map_err(|error| error.to_string())?;
    let manifest_bytes = archive
        .members
        .get("000-manifest.cbor")
        .ok_or_else(|| "missing manifest".to_string())?;
    let manifest = parse_sign1_bytes(manifest_bytes).map_err(|error| error.to_string())?;
    let manifest_payload = manifest
        .payload
        .as_ref()
        .ok_or_else(|| "missing manifest payload".to_string())?;
    let manifest_value = decode_value(manifest_payload).map_err(|error| error.to_string())?;
    let manifest_map = manifest_value
        .as_map()
        .ok_or_else(|| "manifest payload root is not a map".to_string())?;
    let manifest_extensions = encode_manifest_extensions(manifest_map)?;

    let events = archive
        .members
        .get("010-events.cbor")
        .ok_or_else(|| "missing events".to_string())
        .and_then(|bytes| parse_sign1_array(bytes).map_err(|error| error.to_string()))?;
    let payload_blobs = archive
        .members
        .iter()
        .filter_map(|(name, bytes)| {
            let digest_hex = name.strip_prefix("060-payloads/")?.strip_suffix(".bin")?;
            let digest_bytes = hex_decode(digest_hex).ok()?;
            let digest: [u8; 32] = digest_bytes.try_into().ok()?;
            Some((digest, bytes.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let events = events
        .iter()
        .filter_map(|event| {
            let details = decode_event_details(event).ok()?;
            let payload = readable_payload_bytes(&details, &payload_blobs);
            Some(DomainEvent {
                event_type: details.event_type,
                payload,
                canonical_event_hash: details.canonical_event_hash,
                authored_at: details.authored_at,
            })
        })
        .collect();

    Ok(OwnedDomainExport {
        events,
        members: archive.members,
        manifest_extensions,
    })
}

fn encode_manifest_extensions(
    manifest_map: &[(ciborium::Value, ciborium::Value)],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let Some(extensions) =
        map_lookup_optional_map(manifest_map, "extensions").map_err(|error| error.to_string())?
    else {
        return Ok(BTreeMap::new());
    };
    let mut encoded = BTreeMap::new();
    for (key, value) in extensions {
        let Some(uri) = key.as_text() else {
            continue;
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).map_err(|error| error.to_string())?;
        encoded.insert(uri.to_string(), bytes);
    }
    Ok(encoded)
}

/// Verifies a complete export ZIP.
pub fn verify_export_zip(export_zip: &[u8]) -> VerificationReport {
    verify_export_zip_with_record_validator(export_zip, &())
}

/// Verifies a complete export ZIP, threading a `RecordValidator` so the
/// validator's `response_proof_resolver()` reaches Core's
/// certificate-finalization step. Used internally by
/// [`verify_export_zip_with_validator`].
pub(crate) fn verify_export_zip_with_record_validator(
    export_zip: &[u8],
    record_validator: &dyn RecordValidator,
) -> VerificationReport {
    let archive = match parse_export_zip(export_zip) {
        Ok(archive) => archive,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ExportZipInvalid,
                format!("failed to open export ZIP: {error}"),
            );
        }
    };

    let signing_key_registry_bytes = match archive.members.get("030-signing-key-registry.cbor") {
        Some(bytes) => bytes,
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::MissingSigningKeyRegistry,
                "export is missing 030-signing-key-registry.cbor",
            );
        }
    };
    let (registry, non_signing_registry) = match parse_key_registry(signing_key_registry_bytes) {
        Ok(maps) => maps,
        Err(error) => {
            // Core §8.7.3 step 3 / TR-CORE-048: structural shape failures
            // surface as their typed `tamper_kind` (e.g.
            // `key_entry_attributes_shape_mismatch`) rather than the
            // generic `signing_key_registry_invalid` so tamper vectors can
            // pin them. Decode failures with no typed kind keep the
            // generic kind for back-compat with existing fixtures.
            let failure_kind = error
                .kind()
                .map(VerifyErrorKind::verification_failure_kind)
                .unwrap_or(VerificationFailureKind::SigningKeyRegistryInvalid);
            return VerificationReport::fatal(
                failure_kind,
                format!("failed to decode signing-key registry: {error}"),
            );
        }
    };

    let manifest_bytes = match archive.members.get("000-manifest.cbor") {
        Some(bytes) => bytes,
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::MissingManifest,
                "export is missing 000-manifest.cbor",
            );
        }
    };
    let manifest = match parse_sign1_bytes(manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestStructureInvalid,
                format!("manifest is not a valid COSE_Sign1 envelope: {error}"),
            );
        }
    };

    if manifest.alg != ALG_EDDSA
        || manifest.suite_id != SUITE_ID_PHASE_1_I128
        || manifest.artifact_type != ArtifactType::Manifest
    {
        return VerificationReport::fatal(
            VerificationFailureKind::UnsupportedSuite,
            format!(
                "manifest protected header does not match the Trellis Phase-1 manifest suite; artifact_type={}",
                manifest.artifact_type
            ),
        );
    }

    let manifest_public_key = match registry.get(&manifest.kid) {
        Some(entry) => entry.public_key,
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::UnresolvableManifestKid,
                "manifest kid is not resolvable via the embedded signing-key registry",
            );
        }
    };
    if !verify_signature(&manifest, manifest_public_key) {
        return VerificationReport::fatal(
            VerificationFailureKind::ManifestSignatureInvalid,
            "manifest COSE signature is invalid",
        );
    }

    let manifest_payload_bytes = match &manifest.payload {
        Some(bytes) => bytes,
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadMissing,
                "manifest payload is detached, which is out of scope for Phase 1",
            );
        }
    };
    let manifest_payload = match decode_value(manifest_payload_bytes) {
        Ok(value) => value,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("failed to decode manifest payload: {error}"),
            );
        }
    };
    let manifest_map = match manifest_payload.as_map() {
        Some(map) => map,
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                "manifest payload root is not a map",
            );
        }
    };

    // ADR 0008 §"Phase-1 verifier obligation" — dispatched verifier.
    // Path-(b): digest-binds only, no `source_ref` resolution.
    // `c2pa-manifest@v1` and `did-key-view@v1` dispatch; inactive
    // registered kinds short-circuit with `interop_sidecar_phase_1_locked`.
    // Outcomes accumulate into `interop_sidecars` for dispatched entries; lock-off,
    // unknown-kind, derivation-version-unknown, path-invalid,
    // content-mismatch, and unlisted-file all short-circuit via
    // `VerificationReport::fatal` (Core §19.1 / TR-CORE-145, 163..167).
    let interop_sidecars = match verify_interop_sidecars(manifest_map, &archive) {
        Ok(outcomes) => outcomes,
        Err(report) => return report,
    };

    let required_digests = [
        ("010-events.cbor", "events_digest"),
        ("020-inclusion-proofs.cbor", "inclusion_proofs_digest"),
        ("025-consistency-proofs.cbor", "consistency_proofs_digest"),
        (
            "030-signing-key-registry.cbor",
            "signing_key_registry_digest",
        ),
        ("040-checkpoints.cbor", "checkpoints_digest"),
    ];
    for (member_name, field_name) in required_digests {
        let expected = match map_lookup_fixed_bytes(manifest_map, field_name, 32) {
            Ok(bytes) => bytes,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("manifest is missing {field_name}: {error}"),
                );
            }
        };
        let actual = match archive.members.get(member_name) {
            Some(bytes) => sha256_bytes(bytes),
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ArchiveIntegrityFailure,
                    format!("export is missing required member {member_name}"),
                );
            }
        };
        if expected.as_slice() != actual {
            return VerificationReport::fatal(
                VerificationFailureKind::ArchiveIntegrityFailure,
                format!("manifest digest mismatch for {member_name}"),
            );
        }
    }

    let registry_bindings = match map_lookup_array(manifest_map, "registry_bindings") {
        Ok(bindings) => bindings,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("manifest registry_bindings are invalid: {error}"),
            );
        }
    };
    let mut parsed_bindings = Vec::new();
    for binding in registry_bindings {
        let binding_map = match binding.as_map() {
            Some(map) => map,
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    "registry binding is not a map",
                );
            }
        };
        let digest = match map_lookup_fixed_bytes(binding_map, "registry_digest", 32) {
            Ok(bytes) => bytes,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("registry binding digest is invalid: {error}"),
                );
            }
        };
        let member_name = format!("050-registries/{}.cbor", hex_string(&digest));
        let actual = match archive.members.get(&member_name) {
            Some(bytes) => sha256_bytes(bytes),
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ArchiveIntegrityFailure,
                    format!("export is missing bound registry member {member_name}"),
                );
            }
        };
        if actual != digest.as_slice() {
            return VerificationReport::fatal(
                VerificationFailureKind::ArchiveIntegrityFailure,
                format!("bound registry digest mismatch for {member_name}"),
            );
        }
        let bound_at_sequence = match map_lookup_u64(binding_map, "bound_at_sequence") {
            Ok(value) => value,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("registry binding bound_at_sequence is invalid: {error}"),
                );
            }
        };
        parsed_bindings.push(RegistryBindingInfo {
            digest_hex: hex_string(&digest),
            bound_at_sequence,
        });
    }
    parsed_bindings.sort_by_key(|binding| binding.bound_at_sequence);

    let mut parsed_registries = BTreeMap::new();
    for binding in &parsed_bindings {
        let member_name = format!("050-registries/{}.cbor", binding.digest_hex);
        let registry_bytes = match archive.members.get(&member_name) {
            Some(bytes) => bytes,
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ArchiveIntegrityFailure,
                    format!("export is missing bound registry member {member_name}"),
                );
            }
        };
        match parse_bound_registry(registry_bytes) {
            Ok(registry) => {
                parsed_registries.insert(binding.digest_hex.clone(), registry);
            }
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::BoundRegistryInvalid,
                    format!("failed to decode {member_name}: {error}"),
                );
            }
        }
    }

    let scope = match map_lookup_bytes(manifest_map, "scope") {
        Ok(bytes) => bytes,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("manifest scope is invalid: {error}"),
            );
        }
    };
    let generated_at = match map_lookup_timestamp(manifest_map, "generated_at") {
        Ok(timestamp) => timestamp,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("manifest generated_at is invalid: {error}"),
            );
        }
    };

    let events = match archive.members.get("010-events.cbor") {
        Some(bytes) => match parse_sign1_array(bytes) {
            Ok(events) => events,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::EventsInvalid,
                    format!("failed to decode 010-events.cbor: {error}"),
                );
            }
        },
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::ArchiveIntegrityFailure,
                "export is missing 010-events.cbor after manifest digest verification",
            );
        }
    };
    if let Err(message) = verify_seal_fence_extension(manifest_map, &scope, &events, &archive) {
        return VerificationReport::fatal(VerificationFailureKind::ManifestPayloadInvalid, message);
    }
    let payload_blobs = archive
        .members
        .iter()
        .filter_map(|(name, bytes)| {
            let digest_hex = name.strip_prefix("060-payloads/")?.strip_suffix(".bin")?;
            let digest_bytes = hex_decode(digest_hex).ok()?;
            let digest: [u8; 32] = digest_bytes.try_into().ok()?;
            Some((digest, bytes.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut report = verify_event_set_with_classes(
        &events,
        &registry,
        VerifyEventSetOptions {
            non_signing_registry: Some(&non_signing_registry),
            initial_posture_declaration: None,
            posture_declaration: None,
            classify_tamper: false,
            expected_ledger_scope: Some(scope.as_slice()),
            payload_blobs: Some(&payload_blobs),
            record_validator,
        },
    )
    .trellis;
    // ADR 0008 / Core §18.3a — Wave 25 dispatched-verifier outcomes
    // accumulate here. `verify_interop_sidecars` already short-circuited
    // any fatal lock-off / unknown-kind / digest-mismatch / unlisted-file
    // / path-invalid / version-unknown failures via `VerificationReport::fatal`,
    // so what reaches this site is the per-entry success slice. The
    // export-archive integrity fold below treats absent failures as
    // pass-through; non-fatal failures localize per-entry in
    // `outcome.failures` and collapse to integrity-true (the dispatched
    // path-(b) is digest-binds-only — there is no sub-fatal failure
    // surface today).
    report.interop_sidecars = interop_sidecars;
    if let Some(extension) = match parse_attachment_export_extension(manifest_map) {
        Ok(extension) => extension,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("attachment export extension is invalid: {error}"),
            );
        }
    } {
        verify_attachment_manifest(&archive, &events, &extension, &mut report);
    }
    if let Some(extension) = match parse_erasure_evidence_export_extension(manifest_map) {
        Ok(extension) => extension,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("erasure export extension is invalid: {error}"),
            );
        }
    } {
        verify_erasure_evidence_catalog(&archive, &events, &extension, &mut report);
    }
    // ADR 0007 §"Verifier obligations" step 4 — export-bundle context
    // resolves attachment lineage + recomputes content hash. Runs
    // unconditionally so certificate events that travel without the
    // optional manifest catalog still get step-4 enforcement.
    verify_certificate_attachment_lineage(&events, &payload_blobs, &mut report);
    if let Some(extension) = match parse_certificate_export_extension(manifest_map) {
        Ok(extension) => extension,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("certificate export extension is invalid: {error}"),
            );
        }
    } {
        verify_certificate_catalog(&archive, &events, &extension, &mut report);
    }
    let supersession_graph_extension = match parse_supersession_graph_export_extension(manifest_map)
    {
        Ok(extension) => extension,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("supersession graph export extension is invalid: {error}"),
            );
        }
    };
    verify_unbound_supersession_graph(
        &archive,
        supersession_graph_extension.is_some(),
        &mut report,
    );
    if let Some(extension) = supersession_graph_extension {
        verify_supersession_graph(&archive, &events, &scope, &extension, &mut report);
    }
    let open_clocks_extension = match parse_open_clocks_export_extension(manifest_map) {
        Ok(extension) => extension,
        Err(error) => {
            return VerificationReport::fatal(
                VerificationFailureKind::ManifestPayloadInvalid,
                format!("open clocks export extension is invalid: {error}"),
            );
        }
    };
    verify_unbound_open_clocks(&archive, open_clocks_extension.is_some(), &mut report);
    if let Some(extension) = open_clocks_extension {
        verify_open_clocks(&archive, &extension, generated_at, &mut report);
    }
    verify_clock_segments(&events, &payload_blobs, &mut report);
    for failure in &mut report.event_failures {
        if failure.kind == VerificationFailureKind::ScopeMismatch {
            failure.location = format!("manifest-scope/{}", failure.location);
        }
    }
    for event in &events {
        let details = match decode_event_details(event) {
            Ok(details) => details,
            Err(_) => continue,
        };
        let Some(binding) = parsed_bindings
            .iter()
            .filter(|binding| binding.bound_at_sequence <= details.sequence)
            .max_by_key(|binding| binding.bound_at_sequence)
        else {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::RegistryDigestMismatch,
                hex_string(&details.canonical_event_hash),
            ));
            continue;
        };
        let Some(bound_registry) = parsed_registries.get(&binding.digest_hex) else {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::RegistryDigestMismatch,
                hex_string(&details.canonical_event_hash),
            ));
            continue;
        };
        if !bound_registry
            .event_types
            .iter()
            .any(|value| value == &details.event_type)
            || !bound_registry
                .classifications
                .iter()
                .any(|value| value == &details.classification)
        {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::RegistryDigestMismatch,
                hex_string(&details.canonical_event_hash),
            ));
        }
    }

    let canonical_hashes = events
        .iter()
        .filter_map(|event| event_identity(event).ok())
        .map(|(_, canonical_hash)| canonical_hash)
        .collect::<Vec<_>>();
    let leaf_hashes = canonical_hashes
        .iter()
        .copied()
        .map(merkle_leaf_hash)
        .collect::<Vec<_>>();

    let checkpoints = match archive.members.get("040-checkpoints.cbor") {
        Some(bytes) => match parse_sign1_array(bytes) {
            Ok(checkpoints) => checkpoints,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointsInvalid,
                    format!("failed to decode 040-checkpoints.cbor: {error}"),
                );
            }
        },
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::ArchiveIntegrityFailure,
                "export is missing 040-checkpoints.cbor after manifest digest verification",
            );
        }
    };

    let mut prior_checkpoint_digest: Option<[u8; 32]> = None;
    let mut head_checkpoint_root: Option<[u8; 32]> = None;
    for checkpoint in &checkpoints {
        if checkpoint.alg != ALG_EDDSA
            || checkpoint.suite_id != SUITE_ID_PHASE_1_I128
            || checkpoint.artifact_type != ArtifactType::Checkpoint
        {
            return VerificationReport::fatal(
                VerificationFailureKind::UnsupportedSuite,
                format!(
                    "checkpoint protected header does not match the Trellis Phase-1 checkpoint suite; artifact_type={}",
                    checkpoint.artifact_type
                ),
            );
        }
        let public_key = match registry.get(&checkpoint.kid) {
            Some(entry) => entry.public_key,
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::UnresolvableManifestKid,
                    "checkpoint kid is not resolvable via the embedded signing-key registry",
                );
            }
        };
        if !verify_signature(checkpoint, public_key) {
            return VerificationReport::fatal(
                VerificationFailureKind::CheckpointSignatureInvalid,
                "checkpoint COSE signature is invalid",
            );
        }

        let payload_bytes = match &checkpoint.payload {
            Some(bytes) => bytes.as_slice(),
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointPayloadInvalid,
                    "checkpoint COSE payload is detached, which is out of scope for Phase 1",
                );
            }
        };
        let payload = match decode_value(payload_bytes) {
            Ok(value) => value,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointPayloadInvalid,
                    format!("failed to decode checkpoint payload: {error}"),
                );
            }
        };
        let payload_map = match payload.as_map() {
            Some(map) => map,
            None => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointPayloadInvalid,
                    "checkpoint payload root is not a map",
                );
            }
        };

        let checkpoint_scope = match map_lookup_bytes(payload_map, "scope") {
            Ok(bytes) => bytes,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointPayloadInvalid,
                    format!("checkpoint scope is invalid: {error}"),
                );
            }
        };
        if checkpoint_scope != scope {
            report.checkpoint_failures.push(VerificationFailure::new(
                VerificationFailureKind::ScopeMismatch,
                "checkpoint/scope",
            ));
            continue;
        }

        let tree_size = match map_lookup_u64(payload_map, "tree_size") {
            Ok(value) => value as usize,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointPayloadInvalid,
                    format!("checkpoint tree_size is invalid: {error}"),
                );
            }
        };
        if tree_size == 0 || tree_size > leaf_hashes.len() {
            report.checkpoint_failures.push(VerificationFailure::new(
                VerificationFailureKind::TreeSizeInvalid,
                format!("checkpoint/tree_size/{tree_size}"),
            ));
            continue;
        }

        let expected_root = merkle_root(&leaf_hashes[..tree_size]);
        let actual_root = match map_lookup_fixed_bytes(payload_map, "tree_head_hash", 32) {
            Ok(bytes) => bytes_array(&bytes),
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::CheckpointPayloadInvalid,
                    format!("checkpoint tree_head_hash is invalid: {error}"),
                );
            }
        };
        if expected_root != actual_root {
            report.checkpoint_failures.push(VerificationFailure::new(
                VerificationFailureKind::CheckpointRootMismatch,
                format!("checkpoint/tree_size/{tree_size}"),
            ));
        }

        let digest = checkpoint_digest(&scope, payload_bytes);
        if let Some(previous) = prior_checkpoint_digest {
            let actual_prev = match map_lookup_fixed_bytes(payload_map, "prev_checkpoint_hash", 32)
            {
                Ok(bytes) => bytes_array(&bytes),
                Err(error) => {
                    return VerificationReport::fatal(
                        VerificationFailureKind::CheckpointPayloadInvalid,
                        format!("checkpoint prev_checkpoint_hash is invalid: {error}"),
                    );
                }
            };
            if previous != actual_prev {
                report.checkpoint_failures.push(VerificationFailure::new(
                    VerificationFailureKind::PrevCheckpointHashMismatch,
                    format!("checkpoint/tree_size/{tree_size}"),
                ));
            }
        }
        prior_checkpoint_digest = Some(digest);
        head_checkpoint_root = Some(actual_root);
    }

    let head_checkpoint_digest =
        match map_lookup_fixed_bytes(manifest_map, "head_checkpoint_digest", 32) {
            Ok(bytes) => bytes_array(&bytes),
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ManifestPayloadInvalid,
                    format!("manifest head_checkpoint_digest is invalid: {error}"),
                );
            }
        };
    if prior_checkpoint_digest != Some(head_checkpoint_digest) {
        report.checkpoint_failures.push(VerificationFailure::new(
            VerificationFailureKind::HeadCheckpointDigestMismatch,
            "manifest/head_checkpoint_digest",
        ));
    }

    let inclusion_map = match archive.members.get("020-inclusion-proofs.cbor") {
        Some(bytes) => match decode_value(bytes) {
            Ok(value) => value,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::InclusionProofsInvalid,
                    format!("failed to decode 020-inclusion-proofs.cbor: {error}"),
                );
            }
        },
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::ArchiveIntegrityFailure,
                "export is missing 020-inclusion-proofs.cbor after manifest digest verification",
            );
        }
    };
    if let Some(proofs) = inclusion_map.as_map() {
        let expected_root = head_checkpoint_root.unwrap_or([0u8; 32]);
        for (_, proof_value) in proofs {
            let proof_map = match proof_value.as_map() {
                Some(map) => map,
                None => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::InclusionProofInvalid,
                        "proof/map",
                    ));
                    continue;
                }
            };
            let tree_size = match map_lookup_u64(proof_map, "tree_size") {
                Ok(value) => value as usize,
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::InclusionProofInvalid,
                        "proof/tree_size",
                    ));
                    continue;
                }
            };
            if tree_size != leaf_hashes.len() {
                report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::InclusionProofInvalid,
                    format!("proof/tree_size/{tree_size}"),
                ));
                continue;
            }
            let leaf_index = match map_lookup_u64(proof_map, "leaf_index") {
                Ok(value) => value as usize,
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::InclusionProofInvalid,
                        "proof/leaf_index",
                    ));
                    continue;
                }
            };
            if leaf_index >= leaf_hashes.len() {
                report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::InclusionProofInvalid,
                    format!("proof/index/{leaf_index}"),
                ));
                continue;
            }
            let leaf_hash = match map_lookup_fixed_bytes(proof_map, "leaf_hash", 32) {
                Ok(bytes) => bytes_array(&bytes),
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::InclusionProofInvalid,
                        format!("proof/index/{leaf_index}"),
                    ));
                    continue;
                }
            };
            let audit_path_values = match map_lookup_array(proof_map, "audit_path") {
                Ok(path) => path,
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::InclusionProofInvalid,
                        format!("proof/index/{leaf_index}"),
                    ));
                    continue;
                }
            };
            let audit_path = match digest_path_from_values(audit_path_values) {
                Ok(nodes) => nodes,
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::InclusionProofInvalid,
                        format!("proof/index/{leaf_index}/audit_path"),
                    ));
                    continue;
                }
            };
            let matches_leaf = leaf_hash == leaf_hashes[leaf_index];
            let matches_root = root_from_inclusion_proof(
                leaf_index as u64,
                tree_size as u64,
                leaf_hash,
                &audit_path,
            )
            .is_ok_and(|root| root == expected_root);
            if !matches_leaf || !matches_root {
                report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::InclusionProofMismatch,
                    format!("proof/index/{leaf_index}"),
                ));
            }
        }
    }

    let consistency_value = match archive.members.get("025-consistency-proofs.cbor") {
        Some(bytes) => match decode_value(bytes) {
            Ok(value) => value,
            Err(error) => {
                return VerificationReport::fatal(
                    VerificationFailureKind::ConsistencyProofsInvalid,
                    format!("failed to decode 025-consistency-proofs.cbor: {error}"),
                );
            }
        },
        None => {
            return VerificationReport::fatal(
                VerificationFailureKind::ArchiveIntegrityFailure,
                "export is missing 025-consistency-proofs.cbor after manifest digest verification",
            );
        }
    };
    if let Some(records) = consistency_value.as_array() {
        for record in records {
            let record_map = match record.as_map() {
                Some(map) => map,
                None => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ConsistencyProofInvalid,
                        "consistency/map",
                    ));
                    continue;
                }
            };
            let from_tree_size = map_lookup_u64(record_map, "from_tree_size").unwrap_or(0) as usize;
            let to_tree_size = map_lookup_u64(record_map, "to_tree_size").unwrap_or(0) as usize;
            let proof_path_values = match map_lookup_array(record_map, "proof_path") {
                Ok(path) => path,
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ConsistencyProofInvalid,
                        format!("consistency/{from_tree_size}-{to_tree_size}/proof_path"),
                    ));
                    continue;
                }
            };
            let location = format!("consistency/{from_tree_size}-{to_tree_size}");
            if from_tree_size == 0 {
                report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::ConsistencyProofInvalid,
                    format!("{location}/from_zero"),
                ));
                continue;
            }
            if from_tree_size >= to_tree_size || to_tree_size > leaf_hashes.len() {
                report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::ConsistencyProofInvalid,
                    location.clone(),
                ));
                continue;
            }
            let proof_path = match digest_path_from_values(proof_path_values) {
                Ok(nodes) => nodes,
                Err(_) => {
                    report.proof_failures.push(VerificationFailure::new(
                        VerificationFailureKind::ConsistencyProofInvalid,
                        format!("{location}/proof_path"),
                    ));
                    continue;
                }
            };
            let root_old = merkle_root(&leaf_hashes[..from_tree_size]);
            let root_new = merkle_root(&leaf_hashes[..to_tree_size]);
            match root_from_consistency_proof(
                from_tree_size as u64,
                to_tree_size as u64,
                root_old,
                &proof_path,
            ) {
                Ok(computed) if computed == root_new => {}
                Ok(_) => report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::ConsistencyProofMismatch,
                    location,
                )),
                Err(_) => report.proof_failures.push(VerificationFailure::new(
                    VerificationFailureKind::ConsistencyProofInvalid,
                    location,
                )),
            }
        }
    }

    report.structure_verified = true;
    report.integrity_verified = VerificationReport::integrity_verified_from_parts(
        &report.event_failures,
        &report.checkpoint_failures,
        &report.proof_failures,
        &report.posture_transitions,
        &report.erasure_evidence,
        &report.certificates_of_completion,
        &report.user_content_attestations,
        &report.interop_sidecars,
    );
    report.readability_verified = true;
    report
}

fn verify_seal_fence_extension(
    manifest_map: &[(ciborium::Value, ciborium::Value)],
    scope: &[u8],
    events: &[ParsedSign1],
    archive: &ExportArchive,
) -> Result<(), String> {
    let extension = parse_seal_fence_export_extension(manifest_map)
        .map_err(|error| format!("seal fence export extension is invalid: {error}"))?;
    let Some(extension) = extension else {
        return Ok(());
    };
    if extension.bundle_scope != scope {
        return Err(
            "seal fence export extension bundle_scope does not match manifest scope".into(),
        );
    }
    if extension.seal_version == 0 {
        return Err("seal fence export extension seal_version must be positive".into());
    }
    let manifest_tree_size =
        map_lookup_u64(manifest_map, "tree_size").map_err(|error| error.to_string())?;
    if extension.event_count != manifest_tree_size {
        return Err(format!(
            "seal fence export extension event_count {} does not match manifest tree_size {manifest_tree_size}",
            extension.event_count
        ));
    }
    let event_count =
        u64::try_from(events.len()).map_err(|_| "seal fence event count exceeds u64")?;
    if extension.event_count != event_count {
        return Err(format!(
            "seal fence export extension event_count {} does not match events member count {event_count}",
            extension.event_count
        ));
    }
    let high_water_event = events
        .last()
        .ok_or_else(|| "seal fence export extension requires at least one event".to_string())?;
    let high_water_details =
        decode_event_details(high_water_event).map_err(|error| error.to_string())?;
    if extension.high_water_sequence != high_water_details.sequence {
        return Err(format!(
            "seal fence export extension high_water_sequence {} does not match final event sequence {}",
            extension.high_water_sequence, high_water_details.sequence
        ));
    }
    let expected_count = high_water_details
        .sequence
        .checked_add(1)
        .ok_or_else(|| "seal fence high-water sequence overflows event count".to_string())?;
    if extension.event_count != expected_count {
        return Err(format!(
            "seal fence export extension event_count {} does not match high-water sequence {}",
            extension.event_count, extension.high_water_sequence
        ));
    }
    let expected_export_attempt_id = export_attempt_id(
        &extension.bundle_scope,
        extension.seal_version,
        extension.high_water_sequence,
        high_water_details.canonical_event_hash,
    )?;
    if extension.export_attempt_id != expected_export_attempt_id {
        return Err(format!(
            "seal fence export extension export_attempt_id {} does not match deterministic identity {expected_export_attempt_id}",
            extension.export_attempt_id
        ));
    }
    let manifest_head_checkpoint_digest = bytes_array(
        &map_lookup_fixed_bytes(manifest_map, "head_checkpoint_digest", 32)
            .map_err(|error| error.to_string())?,
    );
    if extension.head_checkpoint_digest != manifest_head_checkpoint_digest {
        return Err(
            "seal fence export extension head_checkpoint_digest does not match manifest".into(),
        );
    }
    let manifest_events_digest = bytes_array(
        &map_lookup_fixed_bytes(manifest_map, "events_digest", 32)
            .map_err(|error| error.to_string())?,
    );
    if extension.events_digest != manifest_events_digest {
        return Err("seal fence export extension events_digest does not match manifest".into());
    }
    let actual_events_digest = archive
        .members
        .get("010-events.cbor")
        .map(|bytes| sha256_bytes(bytes))
        .ok_or_else(|| "seal fence export extension cannot resolve events member".to_string())?;
    if extension.events_digest != actual_events_digest {
        return Err(
            "seal fence export extension events_digest does not match events member".into(),
        );
    }
    let actual_policy_closure_digest = archive
        .members
        .get("067-policy-closure.cbor")
        .map(|bytes| sha256_bytes(bytes));
    if extension.policy_closure_digest != actual_policy_closure_digest {
        return Err(
            "seal fence export extension policy_closure_digest does not match closure member"
                .into(),
        );
    }
    Ok(())
}

fn export_attempt_id(
    scope: &[u8],
    seal_version: u64,
    high_water_sequence: u64,
    high_water_event_hash: [u8; 32],
) -> Result<String, String> {
    let material = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("bundle_scope".to_string()),
            ciborium::Value::Bytes(scope.to_vec()),
        ),
        (
            ciborium::Value::Text("seal_version".to_string()),
            ciborium::Value::Integer(seal_version.into()),
        ),
        (
            ciborium::Value::Text("high_water_sequence".to_string()),
            ciborium::Value::Integer(high_water_sequence.into()),
        ),
        (
            ciborium::Value::Text("high_water_event_hash".to_string()),
            ciborium::Value::Bytes(high_water_event_hash.to_vec()),
        ),
    ]);
    let bytes = encode_canonical_cbor_value(&material).map_err(|error| error.to_string())?;
    let digest = domain_separated_sha256(EXPORT_ATTEMPT_DOMAIN, &bytes);
    Ok(format!("sha256:{}", hex_string(&digest)))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use ciborium::Value;
    use integrity_bundle::{Bundle, BundleEntry, read_stored_zip};
    use integrity_cose::{
        decode_cose_sign1, sig_structure_bytes, sign_ed25519, sign1_bytes,
        substrate_protected_header,
    };
    use trellis_export_writer::{
        ExportSealFence, SigningKeyMaterial as WriterSigningKey, export_001_writer_input,
        write_export,
    };
    use trellis_types::{
        ArtifactType, EVENT_DOMAIN, SUITE_ID_PHASE_1, domain_separated_sha256, encode_bstr,
        encode_canonical_cbor_value, encode_tstr, encode_uint,
    };

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum SealFenceTamper {
        IdentityRule,
        ExportAttemptId,
        EventsDigest,
        HeadCheckpointDigest,
        PolicyClosureDigest,
    }

    #[test]
    fn verify_export_zip_rejects_tampered_seal_fence_fields() {
        let cases = [
            (
                SealFenceTamper::IdentityRule,
                "identity_rule is unsupported",
            ),
            (
                SealFenceTamper::ExportAttemptId,
                "export_attempt_id sha256:wrong",
            ),
            (
                SealFenceTamper::EventsDigest,
                "events_digest does not match manifest",
            ),
            (
                SealFenceTamper::HeadCheckpointDigest,
                "head_checkpoint_digest does not match manifest",
            ),
            (
                SealFenceTamper::PolicyClosureDigest,
                "policy_closure_digest does not match closure member",
            ),
        ];

        for (tamper, expected_warning) in cases {
            let (zip_bytes, signing_key) = sealed_export_package();
            let tampered = tamper_manifest_seal_fence(&zip_bytes, &signing_key, tamper);

            let report = verify_export_zip(&tampered);

            assert!(
                !report.structure_verified,
                "{tamper:?} should fail structure verification: {report:#?}"
            );
            assert_eq!(
                report.event_failures.first().map(|failure| failure.kind),
                Some(VerificationFailureKind::ManifestPayloadInvalid),
                "{tamper:?} should fail as manifest payload invalid: {report:#?}"
            );
            assert!(
                report
                    .warnings
                    .iter()
                    .any(|warning| warning.contains(expected_warning)),
                "{tamper:?} should include {expected_warning:?}: {report:#?}"
            );
        }
    }

    fn sealed_export_package() -> (Vec<u8>, WriterSigningKey) {
        let mut input = export_001_writer_input(&fixtures_root());
        let event_count = u64::try_from(input.events.len()).expect("fixture event count fits u64");
        let high_water_event = input.events.last().expect("fixture has events");
        let high_water_sequence = high_water_event.sequence();
        let high_water_event_hash =
            canonical_event_hash(&input.scope, high_water_event.canonical_event());
        let export_attempt_id = export_attempt_id(
            &input.scope,
            event_count,
            high_water_sequence,
            high_water_event_hash,
        )
        .expect("export attempt id");
        input.seal_fence = Some(ExportSealFence {
            bundle_scope: input.scope.clone(),
            export_attempt_id,
            seal_version: event_count,
            event_count,
            high_water_sequence,
        });
        let signing_key = input.signing_key.clone();
        let package = write_export(input).expect("write sealed export");
        let report = verify_export_zip(&package.zip_bytes);
        assert!(
            report.structure_verified && report.integrity_verified,
            "fixture sealed export should verify: {report:#?}"
        );
        (package.zip_bytes, signing_key)
    }

    fn tamper_manifest_seal_fence(
        zip_bytes: &[u8],
        signing_key: &WriterSigningKey,
        tamper: SealFenceTamper,
    ) -> Vec<u8> {
        let entries = read_stored_zip(zip_bytes).expect("read fixture export ZIP");
        let mut bundle = Bundle::new();
        for entry in entries {
            let bytes = if entry.path().ends_with("000-manifest.cbor") {
                resign_tampered_manifest(entry.bytes(), signing_key, tamper)
            } else {
                entry.bytes().to_vec()
            };
            bundle.add_entry(BundleEntry::new(entry.path().to_string(), bytes));
        }
        bundle.to_zip_bytes().expect("rebuild tampered ZIP")
    }

    fn resign_tampered_manifest(
        manifest_bytes: &[u8],
        signing_key: &WriterSigningKey,
        tamper: SealFenceTamper,
    ) -> Vec<u8> {
        let sign1 = decode_cose_sign1(manifest_bytes).expect("decode manifest sign1");
        let payload = sign1.payload().expect("manifest payload is embedded");
        let mut manifest =
            trellis_types::decode_cbor_value(payload).expect("decode manifest payload");
        let manifest_map = value_map_mut(&mut manifest);
        let extensions = value_map_mut(map_entry_mut(manifest_map, "extensions"));
        let seal_fence = value_map_mut(map_entry_mut(extensions, "trellis.export.seal-fence.v1"));
        match tamper {
            SealFenceTamper::IdentityRule => {
                *map_entry_mut(seal_fence, "identity_rule") =
                    Value::Text("trellis-export-seal-fence-test".to_string());
            }
            SealFenceTamper::ExportAttemptId => {
                *map_entry_mut(seal_fence, "export_attempt_id") =
                    Value::Text("sha256:wrong".to_string());
            }
            SealFenceTamper::EventsDigest => {
                *map_entry_mut(seal_fence, "events_digest") = Value::Bytes(vec![0xaa; 32]);
            }
            SealFenceTamper::HeadCheckpointDigest => {
                *map_entry_mut(seal_fence, "head_checkpoint_digest") = Value::Bytes(vec![0xbb; 32]);
            }
            SealFenceTamper::PolicyClosureDigest => {
                *map_entry_mut(seal_fence, "policy_closure_digest") = Value::Bytes(vec![0xcc; 32]);
            }
        }

        let payload_bytes =
            encode_canonical_cbor_value(&manifest).expect("canonical manifest payload");
        let protected = substrate_protected_header(
            -8,
            &signing_key.kid(),
            SUITE_ID_PHASE_1,
            ArtifactType::Manifest.cose_value(),
        );
        let signature = sign_ed25519(
            signing_key.private_seed,
            &sig_structure_bytes(&protected, &payload_bytes),
        );
        sign1_bytes(&protected, &payload_bytes, signature)
    }

    fn value_map_mut(value: &mut Value) -> &mut Vec<(Value, Value)> {
        match value {
            Value::Map(entries) => entries,
            _ => panic!("expected CBOR map"),
        }
    }

    fn map_entry_mut<'a>(map: &'a mut [(Value, Value)], key: &str) -> &'a mut Value {
        map.iter_mut()
            .find(|(entry_key, _)| entry_key.as_text() == Some(key))
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing map key {key}"))
    }

    fn canonical_event_hash(scope: &[u8], canonical_event_bytes: &[u8]) -> [u8; 32] {
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

    fn fixtures_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("trellis/fixtures/vectors")
    }
}

#[cfg(test)]
#[expect(
    dead_code,
    reason = "retained for downstream Trellis verifier test fixtures"
)]
pub(crate) fn export_archive_for_tests(members: BTreeMap<String, Vec<u8>>) -> ExportArchive {
    ExportArchive { members }
}

/// Parses a Trellis export ZIP into [`ExportArchive`] members.
///
/// **Layout contract:** each ZIP entry name must contain exactly one `/`
/// separating `{export_root}/` from the relative member path. Top-level
/// entries, extra leading segments, or nested roots are rejected so member
/// paths stay stable across toolchains.
pub(crate) fn parse_export_zip(bytes: &[u8]) -> Result<ExportArchive, VerifyError> {
    let mut members = BTreeMap::new();
    for entry in read_stored_zip(bytes)
        .map_err(|error| VerifyError::new(format!("failed to parse ZIP: {error}")))?
    {
        let Some((_, relative_name)) = entry.path().split_once('/') else {
            return Err(VerifyError::new(
                "ZIP member does not live under one export root",
            ));
        };
        members.insert(relative_name.to_string(), entry.bytes().to_vec());
    }
    Ok(ExportArchive { members })
}

/// ADR 0072 topology: duplicate manifest rows, prior resolution, strict prior-before-binding
/// order in the exported event array, and cycles in the prior-pointer graph.
pub(crate) fn attachment_manifest_topology_failures(
    entries: &[AttachmentManifestEntry],
    hash_to_index: &BTreeMap<[u8; 32], usize>,
) -> Vec<VerificationFailure> {
    let mut failures = Vec::new();

    let mut seen_bindings = BTreeSet::new();
    for entry in entries {
        if !seen_bindings.insert(entry.binding_event_hash) {
            failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentManifestDuplicateBinding,
                hex_string(&entry.binding_event_hash),
            ));
        }
    }

    let mut adj: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
    for entry in entries {
        let Some(prior_hash) = entry.prior_binding_hash else {
            continue;
        };
        if hash_to_index.contains_key(&entry.binding_event_hash)
            && hash_to_index.contains_key(&prior_hash)
        {
            adj.entry(entry.binding_event_hash)
                .or_default()
                .push(prior_hash);
        }
    }
    if binding_lineage_graph_has_cycle(&adj) {
        failures.push(VerificationFailure::new(
            VerificationFailureKind::AttachmentBindingLineageCycle,
            "061-attachments.cbor",
        ));
    }

    for entry in entries {
        let Some(&current_idx) = hash_to_index.get(&entry.binding_event_hash) else {
            continue;
        };
        let Some(prior_hash) = entry.prior_binding_hash else {
            continue;
        };
        let Some(&prior_idx) = hash_to_index.get(&prior_hash) else {
            failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentPriorBindingUnresolved,
                hex_string(&entry.binding_event_hash),
            ));
            continue;
        };
        if prior_idx >= current_idx {
            failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentPriorBindingForwardReference,
                hex_string(&entry.binding_event_hash),
            ));
        }
    }

    failures
}

pub(crate) fn verify_attachment_manifest(
    archive: &ExportArchive,
    events: &[ParsedSign1],
    extension: &AttachmentExportExtension,
    report: &mut VerificationReport,
) {
    let Some(manifest_bytes) = archive.members.get("061-attachments.cbor") else {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::MissingAttachmentManifest,
            "061-attachments.cbor",
        ));
        return;
    };
    let actual_digest = sha256_bytes(manifest_bytes);
    if actual_digest.as_slice() != extension.manifest_digest {
        report.event_failures.push(VerificationFailure::new(
            VerificationFailureKind::AttachmentManifestDigestMismatch,
            "061-attachments.cbor",
        ));
    }

    let entries = match parse_attachment_manifest_entries(manifest_bytes) {
        Ok(entries) => entries,
        Err(error) => {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentManifestInvalid,
                format!("061-attachments.cbor/{error}"),
            ));
            return;
        }
    };
    let event_details = events
        .iter()
        .filter_map(|event| decode_event_details(event).ok())
        .collect::<Vec<_>>();

    let mut hash_to_index: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if let Ok(details) = decode_event_details(event) {
            hash_to_index.insert(details.canonical_event_hash, index);
        }
    }
    for failure in attachment_manifest_topology_failures(&entries, &hash_to_index) {
        report.event_failures.push(failure);
    }

    for entry in &entries {
        let matching_events = event_details
            .iter()
            .filter(|details| details.canonical_event_hash == entry.binding_event_hash)
            .collect::<Vec<_>>();
        if matching_events.len() != 1 {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentBindingEventUnresolved,
                hex_string(&entry.binding_event_hash),
            ));
            continue;
        }
        let details = matching_events[0];
        let Some(binding) = details.attachment_binding() else {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentBindingMissing,
                hex_string(&entry.binding_event_hash),
            ));
            continue;
        };
        if !attachment_entry_matches_binding(entry, binding) {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentBindingMismatch,
                hex_string(&entry.binding_event_hash),
            ));
        }
        if entry.payload_content_hash != details.content_hash
            || binding.payload_content_hash != details.content_hash
        {
            report.event_failures.push(VerificationFailure::new(
                VerificationFailureKind::AttachmentPayloadHashMismatch,
                hex_string(&entry.binding_event_hash),
            ));
        }
        if extension.inline_attachments {
            let member = format!(
                "060-payloads/{}.bin",
                hex_string(&entry.payload_content_hash)
            );
            if !archive.members.contains_key(&member) {
                report.event_failures.push(VerificationFailure::new(
                    VerificationFailureKind::MissingAttachmentBody,
                    member,
                ));
            }
        }
    }
}
